"""Evaluate the trained detector and write a report.

Replays the brute-force dataset through the real Service in replay mode and reads
the emitted events, so the measured detection delay and false positives reflect
the full decision logic (confirmation, cooldown, protected IPs), not just raw
scores. Also scores the normal and hard tables to count false positives per hour.
Writes reports/<detector>/<version>/eval.json and eval.md.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import yaml

from detector.config import Config
from detector.features import FEATURE_NAMES
from detector.schema import _parse_ts
from detector.scorer import Scorer
from detector.service import Service


def _capture_events(auth_file: str, models_dir: str, detector: str) -> list[dict]:
    cfg = Config(
        source="file", source_files=[auth_file], sink="stdout",
        enabled_detectors=[detector], models_dir=models_dir, replay=True,
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        Service(cfg).run()
    events = []
    for line in buf.getvalue().splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events


def _count_fp(features_csv: Path, scorer: Scorer) -> tuple[int, int]:
    """Return (false positives, normal-vector count) by scoring each normal/bot row."""
    fp = 0
    normal = 0
    if not features_csv.exists():
        return 0, 0
    with open(features_csv) as f:
        for r in csv.DictReader(f):
            if r["label"] not in ("normal", "attack_other_ip"):
                continue
            normal += 1
            vec = {name: float(r[name]) for name in FEATURE_NAMES}
            score, _ = scorer.score(vec)
            if score >= scorer.threshold:
                fp += 1
    return fp, normal


def evaluate(params: dict, raw: Path, features: Path, models: Path, reports: Path) -> dict:
    detector = params["model"]["detector"]
    version = params["model"]["version"]
    scorer = Scorer.load_production(str(models), detector)

    # Detection on the brute-force capture, through the full service.
    bf_auth = raw / "synth_bf_v1" / "auth.jsonl"
    labels = json.loads((raw / "synth_bf_v1" / "labels.json").read_text())
    attack = labels["attacks"][0]
    a_start = _parse_ts(attack["start"])
    attacker_ips = set(attack["src_ips"])

    events = _capture_events(str(bf_auth), str(models), detector)
    attack_events = [e for e in events if e["src_ip"] in attacker_ips]
    other_events = [e for e in events if e["src_ip"] not in attacker_ips]
    detected = len(attack_events) > 0
    delay = None
    if detected:
        first = min(_parse_ts(e["ts"]) for e in attack_events)
        delay = round(first - a_start, 1)

    # False positives on normal and hard captures.
    fp_normal, n_normal = _count_fp(features / "synth_normal_v1.csv", scorer)
    fp_hard, n_hard = _count_fp(features / "synth_hard_v1.csv", scorer)
    # ~1 hour each capture; FP/hour is the sum over the hours covered.
    fp_total = fp_normal + fp_hard + len(other_events)
    hours = 2.0

    report = {
        "detector": detector,
        "version": version,
        "bruteforce_detected": detected,
        "detection_delay_s_replay": delay,
        "events_on_attacker": len(attack_events),
        "events_on_other_ips": len(other_events),
        "false_positives_normal": fp_normal,
        "false_positives_hard": fp_hard,
        "normal_vectors_scored": n_normal + n_hard,
        "fp_per_hour": round(fp_total / hours, 2),
        "threshold": scorer.threshold,
        "gate_pass": bool(detected and (delay is not None and delay <= 15)
                          and fp_normal == 0 and fp_hard == 0 and len(other_events) == 0),
    }

    out_dir = reports / detector / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "eval.json").write_text(json.dumps(report, indent=2))
    (out_dir / "eval.md").write_text(_markdown(report))
    print(json.dumps(report, indent=2))
    return report


def _markdown(r: dict) -> str:
    status = "PASS" if r["gate_pass"] else "FAIL"
    return (
        f"# Evaluation — {r['detector']} v{r['version']}\n\n"
        f"Gate: **{status}**\n\n"
        f"| Metric | Value |\n|---|---|\n"
        f"| Brute force detected | {r['bruteforce_detected']} |\n"
        f"| Detection delay (replay) | {r['detection_delay_s_replay']} s |\n"
        f"| Events on attacker IP | {r['events_on_attacker']} |\n"
        f"| Events on other IPs (false) | {r['events_on_other_ips']} |\n"
        f"| False positives, normal | {r['false_positives_normal']} |\n"
        f"| False positives, hard | {r['false_positives_hard']} |\n"
        f"| FP per hour | {r['fp_per_hour']} |\n"
        f"| Threshold | {r['threshold']} |\n"
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--params", default="params.yaml")
    ap.add_argument("--raw", default="data/raw")
    ap.add_argument("--features", default="data/features")
    ap.add_argument("--models", default="models")
    ap.add_argument("--reports", default="reports")
    args = ap.parse_args()
    params = yaml.safe_load(Path(args.params).read_text())
    evaluate(params, Path(args.raw), Path(args.features), Path(args.models), Path(args.reports))


if __name__ == "__main__":
    main()
