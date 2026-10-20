"""End-to-end: generate -> build features -> train -> evaluate, assert detection.

Runs the whole offline pipeline on synthetic data in a temp directory, and checks
the gate: the brute force is detected and no event fires on normal traffic.
"""

from pathlib import Path

import yaml

from generator.generate import generate
from training.build_features import build
from training.evaluate import evaluate
from training.train import train


def test_pipeline_detects_bruteforce_without_false_positives(tmp_path: Path):
    raw = tmp_path / "raw"
    feats = tmp_path / "features"
    models = tmp_path / "models"
    reports = tmp_path / "reports"

    for preset in ("synth_normal_v1", "synth_bf_v1", "synth_hard_v1"):
        generate(preset, raw)
        build(preset, raw, feats)

    params = yaml.safe_load((Path(__file__).parents[2] / "params.yaml").read_text())
    uri = f"sqlite:///{tmp_path / 'mlflow.db'}"
    train(params, feats, models, tracking_uri=uri)
    report = evaluate(params, raw, feats, models, reports, tracking_uri=uri)

    assert report["bruteforce_detected"] is True
    assert report["max_detection_delay_s_replay"] <= 15
    assert report["false_positive_events"] == 0
    assert report["gate_pass"] is True

    # MLflow: the run has the eval metrics and the model got the production alias.
    import json

    from mlflow import MlflowClient

    md = json.loads((models / "auth_bruteforce" / "0.1.0" / "metadata.json").read_text())
    client = MlflowClient(tracking_uri=uri)
    run = client.get_run(md["mlflow_run_id"])
    assert run.data.metrics["eval_gate_pass"] == 1.0
    alias = client.get_model_version_by_alias("auth_bruteforce", "production")
    assert str(alias.version) == str(md["mlflow_model_version"])
