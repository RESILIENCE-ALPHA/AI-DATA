"""Build a labelled feature table from a raw dataset.

Slides a tick every 5 s over the capture, computes one vector per active IP, and
labels it from `labels.json` (attacker IP overlapping the 60 s window -> the
attack label; a known bot IP -> `bot`; otherwise `normal`). Writes a CSV so there
is no extra dependency. The same `compute_vectors` is used at serving time.
"""

from __future__ import annotations

import argparse
import csv
import json
from bisect import bisect_right
from pathlib import Path

from detector.features import FEATURE_NAMES, compute_vectors
from detector.schema import _parse_ts
from detector.sources.file import load_records

TICK_S = 5
WINDOW_S = 60


def _load_labels(path: Path) -> dict:
    if not path.exists():
        return {"attacks": [], "protected_ips": [], "bot_ips": []}
    return json.loads(path.read_text())


def _label_for(ip: str, now: float, labels: dict) -> str:
    for atk in labels.get("attacks", []):
        a_start = _parse_ts(atk["start"])
        a_end = _parse_ts(atk["end"])
        overlaps = (now - WINDOW_S) < a_end and now >= a_start
        if overlaps:
            if ip in atk.get("src_ips", []):
                return atk["type"]
            return "attack_other_ip"
    if ip in labels.get("bot_ips", []):
        return "bot"
    return "normal"


def build(dataset: str, raw_root: Path, out_root: Path) -> Path:
    raw_dir = raw_root / dataset
    records = load_records([str(raw_dir / "auth.jsonl")])
    labels = _load_labels(raw_dir / "labels.json")
    if not records:
        raise SystemExit(f"no records in {raw_dir}/auth.jsonl (run the generator first)")

    start, end = records[0].ts, records[-1].ts
    ts_list = [r.ts for r in records]  # sorted, for fast window slicing
    out_root.mkdir(parents=True, exist_ok=True)
    out_path = out_root / f"{dataset}.csv"
    n_rows = 0
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ts", "src_ip", "label", *FEATURE_NAMES])
        t = start + TICK_S
        while t <= end + TICK_S:
            window = records[bisect_right(ts_list, t - 300) : bisect_right(ts_list, t)]
            for ip, vec in compute_vectors(window, t).items():
                label = _label_for(ip, t, labels)
                writer.writerow([f"{t:.3f}", ip, label, *[vec[name] for name in FEATURE_NAMES]])
                n_rows += 1
            t += TICK_S
    print(f"{dataset}: {n_rows} feature rows -> {out_path}")
    return out_path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--raw", default="data/raw")
    ap.add_argument("--out", default="data/features")
    args = ap.parse_args()
    build(args.dataset, Path(args.raw), Path(args.out))


if __name__ == "__main__":
    main()
