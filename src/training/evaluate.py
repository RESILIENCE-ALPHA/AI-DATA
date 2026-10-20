"""Evaluate the trained detector and write a report.

Each evaluation dataset is replayed through the real Service (replay mode), so the
numbers include the whole decision logic: 2-tick confirmation, cooldown, cap.
- detection: first event on the attacker IP, delay from the attack start,
- false positives: events on any other IP that is not a known internet bot,
- bot events: reported apart (flagging a scanner is acceptable).
The training capture (synth_normal_v1) is NOT used for the false-positive gate.
Writes reports/<detector>/<version>/eval.json and eval.md.
"""

from __future__ import annotations

import argparse
import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import yaml

from detector.config import Config
from detector.schema import _parse_ts
from detector.service import Service

EVAL_DATASETS = ("synth_bf_v1", "synth_hard_v1")


def replay_events(auth_file: Path, models_dir: Path, detector: str) -> list[dict]:
    """Run the service in replay mode on one file and return the events it emitted."""
    cfg = Config(
        source="file", source_files=[str(auth_file)], sink="stdout",
        enabled_detectors=[detector], models_dir=str(models_dir), replay=True,
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        Service(cfg).run()
    events = []
    for line in buf.getvalue().splitlines():
        if line.startswith("{"):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events


def _capture_hours(auth_file: Path) -> float:
    lines = auth_file.read_text().splitlines()
    first = _parse_ts(json.loads(lines[0])["createdAt"])
    last = _parse_ts(json.loads(lines[-1])["createdAt"])
    return max((last - first) / 3600.0, 1e-6)


def evaluate(params: dict, raw: Path, features: Path, models: Path, reports: Path) -> dict:
    detector = params["model"]["detector"]
    version = params["model"]["version"]

    per_dataset = {}
    detected_all = True
    delays: list[float] = []
    fp_total = 0
    hours_total = 0.0
    for name in EVAL_DATASETS:
        auth = raw / name / "auth.jsonl"
        labels = json.loads((raw / name / "labels.json").read_text())
        attackers = {ip for a in labels.get("attacks", []) for ip in a["src_ips"]}
        bots = set(labels.get("bot_ips", []))

        events = replay_events(auth, models, detector)
        on_attacker = [e for e in events if e["src_ip"] in attackers]
        on_bots = [e for e in events if e["src_ip"] in bots]
        false_pos = [e for e in events if e["src_ip"] not in attackers | bots]

        delay = None
        if labels.get("attacks"):
            a_start = _parse_ts(labels["attacks"][0]["start"])
            if on_attacker:
                delay = round(min(_parse_ts(e["ts"]) for e in on_attacker) - a_start, 1)
                delays.append(delay)
            else:
                detected_all = False

        hours = _capture_hours(auth)
        fp_total += len(false_pos)
        hours_total += hours
        per_dataset[name] = {
            "events_total": len(events),
            "events_on_attacker": len(on_attacker),
            "detection_delay_s_replay": delay,
            "false_positive_events": len(false_pos),
            "false_positive_ips": sorted({e["src_ip"] for e in false_pos}),
            "bot_events": len(on_bots),
            "capture_hours": round(hours, 2),
        }

    max_delay = max(delays) if delays else None
    report = {
        "detector": detector,
        "version": version,
        "datasets": per_dataset,
        "bruteforce_detected": detected_all and bool(delays),
        "max_detection_delay_s_replay": max_delay,
        "false_positive_events": fp_total,
        "fp_per_hour": round(fp_total / hours_total, 2) if hours_total else None,
        "gate": {"max_delay_s": 15, "max_false_positive_events": 0},
    }
    report["gate_pass"] = bool(
        report["bruteforce_detected"] and max_delay is not None and max_delay <= 15
        and fp_total == 0
    )

    out_dir = reports / detector / version
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "eval.json").write_text(json.dumps(report, indent=2))
    (out_dir / "eval.md").write_text(_markdown(report))
    print(json.dumps(report, indent=2))
    return report


def _markdown(r: dict) -> str:
    lines = [
        f"# Evaluation — {r['detector']} v{r['version']}",
        "",
        f"Gate: **{'PASS' if r['gate_pass'] else 'FAIL'}** "
        f"(brute force detected, delay ≤ {r['gate']['max_delay_s']} s, no false positive)",
        "",
        "| Dataset | Events | On attacker | Delay (s) | False positives | Bot events |",
        "|---|---|---|---|---|---|",
    ]
    for name, d in r["datasets"].items():
        lines.append(
            f"| {name} | {d['events_total']} | {d['events_on_attacker']} | "
            f"{d['detection_delay_s_replay']} | {d['false_positive_events']} | {d['bot_events']} |"
        )
    lines += ["", f"False positives per hour: {r['fp_per_hour']}", ""]
    return "\n".join(lines)


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
