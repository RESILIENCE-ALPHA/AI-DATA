"""Train the auth_bruteforce Isolation Forest on normal traffic only.

Reads the normal feature table, fits a RobustScaler and an Isolation Forest, and
stores the model, the scaler, and a metadata.json holding the feature list,
hyperparameters, the two calibration points of the 0..1 score (raw_ref, raw_thr)
and the scaled median (for the top-feature explanation).

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


def _load_csv(path: Path) -> tuple[list[dict], np.ndarray, list[str]]:
    rows: list[dict] = []
    with open(path) as f:
        for row in csv.DictReader(f):
            rows.append(row)
    vectors = [{name: float(r[name]) for name in FEATURE_NAMES} for r in rows]
    matrix = np.array([transform_row(v) for v in vectors], dtype=float)
    labels = [r["label"] for r in rows]
    return vectors, matrix, labels


def train(params: dict, features_dir: Path, models_dir: Path) -> Path:
    m = params["model"]
    detector = m["detector"]
    version = m["version"]
    normal_csv = features_dir / "synth_normal_v1.csv"
    if not normal_csv.exists():
        raise SystemExit(f"missing {normal_csv}; run `make data features` first")

    _, X_raw, labels = _load_csv(normal_csv)
    normal = X_raw[[i for i, lb in enumerate(labels) if lb in ("normal", "bot")]]
    if len(normal) < 20:
        raise SystemExit(f"only {len(normal)} normal rows; generate more data")

    scaler = RobustScaler().fit(normal)
    X = scaler.transform(normal)

    model = IsolationForest(
        n_estimators=m["n_estimators"],
        max_samples=m["max_samples"],
        contamination=m["contamination"],
        random_state=m["random_state"],
    ).fit(X)

    # Calibration: median normal -> 0.5; just above the most anomalous normal
    # vector -> 0.9 (the decision threshold). The margin leaves room for normal
    # traffic slightly more unusual than anything in the training capture.
    raw_scores = -model.score_samples(X)
    raw_ref = float(np.median(raw_scores))
    raw_thr = float(min(0.99, raw_scores.max() + m.get("threshold_margin", 0.03)))
    scaled_median = np.median(X, axis=0).tolist()

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
        "scaled_median": scaled_median,
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))

    pointer = models_dir / detector / "PRODUCTION"
    pointer.write_text(version)
    print(f"trained {detector} v{version} on {len(normal)} normal rows -> {out_dir}")
    return out_dir


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--params", default="params.yaml")
    ap.add_argument("--features", default="data/features")
    ap.add_argument("--models", default="models")
    args = ap.parse_args()
    params = yaml.safe_load(Path(args.params).read_text())
    train(params, Path(args.features), Path(args.models))


if __name__ == "__main__":
    main()
