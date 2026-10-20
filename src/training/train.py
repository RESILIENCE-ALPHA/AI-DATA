"""Train the auth_bruteforce Isolation Forest on normal traffic only, tracked in MLflow.

Steps:
1. read the normal feature table (normal + internet-bot rows),
2. fit a RobustScaler and an Isolation Forest,
3. compute the two calibration points of the 0..1 score (raw_ref, raw_thr),
4. save model.pkl, scaler.pkl and metadata.json under models/<detector>/<version>/
   (this folder is what the detector service loads),
5. log params, metrics and those files to an MLflow run, and register the model
   in the MLflow Model Registry under the detector's name.

"Normal" includes internet-bot noise: a public server always gets scanned, so the
model must learn that low-rate scanning is background, not an attack. It never
sees the brute force, so detection does not depend on knowing the attack.
"""

from __future__ import annotations

import argparse
import csv
import json
import pickle
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import yaml
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from detector.features import FEATURE_NAMES, transform_row
from training import tracking

TRAINING_DATASET = "synth_normal_v1"


def _load_csv(path: Path) -> tuple[np.ndarray, list[str]]:
    with open(path) as f:
        rows = list(csv.DictReader(f))
    vectors = [{name: float(r[name]) for name in FEATURE_NAMES} for r in rows]
    matrix = np.array([transform_row(v) for v in vectors], dtype=float)
    labels = [r["label"] for r in rows]
    return matrix, labels


def _log_to_mlflow(
    params: dict, model, x_train: np.ndarray, out_dir: Path, metrics: dict,
    tracking_uri: str | None,
) -> tuple[str, str]:
    """Log the run and register the model. Returns (run_id, registry version)."""
    from mlflow.models import infer_signature

    m = params["model"]
    detector = m["detector"]
    mlflow = tracking.setup(detector, tracking_uri)
    with mlflow.start_run(run_name=f"train-{m['version']}") as run:
        mlflow.set_tags({"detector": detector, "detector_version": m["version"]})
        mlflow.log_params({
            "training_dataset": TRAINING_DATASET,
            "n_features": len(FEATURE_NAMES),
            "tick_s": params["features"]["tick_s"],
            "windows_s": params["features"]["windows_s"],
            "history_s": params["features"]["history_s"],
            "n_estimators": m["n_estimators"],
            "max_samples": m["max_samples"],
            "contamination": m["contamination"],
            "random_state": m["random_state"],
            "threshold": m["threshold"],
            "threshold_margin": m.get("threshold_margin", 0.03),
        })
        mlflow.log_metrics(metrics)
        # The files the service loads, kept together in the run.
        mlflow.log_artifacts(str(out_dir), artifact_path="detector_files")
        # The Isolation Forest itself, registered so the registry tracks versions.
        # Saved with skops (safer than pickle); we only trust the tree type that our
        # own Isolation Forest is made of, because we created this file ourselves.
        info = mlflow.sklearn.log_model(
            sk_model=model,
            name="isolation_forest",
            registered_model_name=detector,
            serialization_format="skops",
            skops_trusted_types=["sklearn.tree._tree.Tree"],
            signature=infer_signature(x_train[:5], model.score_samples(x_train[:5])),
        )
        return run.info.run_id, str(info.registered_model_version)


def train(
    params: dict, features_dir: Path, models_dir: Path,
    tracking_uri: str | None = None, use_mlflow: bool = True,
) -> Path:
    m = params["model"]
    detector = m["detector"]
    version = m["version"]
    normal_csv = features_dir / f"{TRAINING_DATASET}.csv"
    if not normal_csv.exists():
        raise SystemExit(f"missing {normal_csv}; run `make data features` first")

    x_all, labels = _load_csv(normal_csv)
    normal = x_all[[i for i, lb in enumerate(labels) if lb in ("normal", "bot")]]
    if len(normal) < 20:
        raise SystemExit(f"only {len(normal)} normal rows; generate more data")

    scaler = RobustScaler().fit(normal)
    x_train = scaler.transform(normal)

    model = IsolationForest(
        n_estimators=m["n_estimators"],
        max_samples=m["max_samples"],
        contamination=m["contamination"],
        random_state=m["random_state"],
    ).fit(x_train)

    # Calibration: median normal -> 0.5; just above the most anomalous normal
    # vector -> 0.9 (the decision threshold). The margin leaves room for normal
    # traffic slightly more unusual than anything in the training capture.
    raw_scores = -model.score_samples(x_train)
    raw_ref = float(np.median(raw_scores))
    raw_max = float(raw_scores.max())
    raw_thr = float(min(0.99, raw_max + m.get("threshold_margin", 0.03)))

    out_dir = models_dir / detector / version
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "model.pkl", "wb") as f:
        pickle.dump(model, f)
    with open(out_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    metadata = {
        "detector": detector,
        "version": version,
        "trained_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "training_dataset": TRAINING_DATASET,
        "feature_names": FEATURE_NAMES,
        "tick_s": params["features"]["tick_s"],
        "windows_s": params["features"]["windows_s"],
        "history_s": params["features"]["history_s"],
        "hyperparameters": {k: m[k] for k in
                            ("n_estimators", "max_samples", "contamination", "random_state")},
        "threshold": m["threshold"],
        "training_rows": int(len(normal)),
        "raw_ref": raw_ref,
        "raw_thr": raw_thr,
        "scaled_median": np.median(x_train, axis=0).tolist(),
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))

    if use_mlflow:
        metrics = {"training_rows": float(len(normal)), "raw_ref": raw_ref,
                   "raw_max_normal": raw_max, "raw_thr": raw_thr}
        run_id, reg_version = _log_to_mlflow(params, model, x_train, out_dir, metrics,
                                             tracking_uri)
        metadata["mlflow_run_id"] = run_id
        metadata["mlflow_model_version"] = reg_version
        (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
        print(f"mlflow: run {run_id}, registered {detector} version {reg_version}")

    (models_dir / detector / "PRODUCTION").write_text(version)
    print(f"trained {detector} v{version} on {len(normal)} normal rows -> {out_dir}")
    return out_dir


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--params", default="params.yaml")
    ap.add_argument("--features", default="data/features")
    ap.add_argument("--models", default="models")
    ap.add_argument("--no-mlflow", action="store_true", help="skip MLflow logging")
    args = ap.parse_args()
    params = yaml.safe_load(Path(args.params).read_text())
    train(params, Path(args.features), Path(args.models), use_mlflow=not args.no_mlflow)


if __name__ == "__main__":
    main()
