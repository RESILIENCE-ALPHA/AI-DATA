"""Load a trained model and score vectors to a 0..1 anomaly score.

Isolation Forest returns a raw anomaly value between 0 and 1 (higher = easier to
isolate). We rescale it with two points learned on normal training traffic:
- `raw_ref`, the median raw score of normal traffic, maps to 0.50,
- `raw_thr`, just above the most anomalous normal vector, maps to 0.90.
So the decision threshold is always 0.90 and 0.97+ means far beyond anything
seen in normal traffic. The model's feature list must match the running code,
or loading fails (no train/serve skew).
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path

from .features import FEATURE_NAMES, transform_row


class Scorer:
    def __init__(self, model, scaler, metadata: dict) -> None:
        self.model = model
        self.scaler = scaler
        self.metadata = metadata
        self.detector = metadata["detector"]
        self.model_version = metadata["version"]
        self.threshold = float(metadata.get("threshold", 0.90))
        self.raw_ref = float(metadata["raw_ref"])
        self.raw_thr = float(metadata["raw_thr"])
        self._median = metadata.get("scaled_median", [0.0] * len(FEATURE_NAMES))
        if metadata.get("feature_names") != FEATURE_NAMES:
            raise ValueError(
                f"Model feature list differs from code for detector {self.detector}; "
                "retrain or update features.py."
            )

    @classmethod
    def load(cls, model_dir: str | Path) -> Scorer:
        d = Path(model_dir)
        with open(d / "model.pkl", "rb") as f:
            model = pickle.load(f)
        with open(d / "scaler.pkl", "rb") as f:
            scaler = pickle.load(f)
        metadata = json.loads((d / "metadata.json").read_text())
        return cls(model, scaler, metadata)

    @classmethod
    def load_production(cls, models_dir: str | Path, detector: str) -> Scorer:
        base = Path(models_dir) / detector
        pointer = base / "PRODUCTION"
        version = pointer.read_text().strip() if pointer.exists() else None
        if version:
            return cls.load(base / version)
        # Fallback: the single version folder present.
        versions = [p for p in base.iterdir() if p.is_dir()]
        if not versions:
            raise FileNotFoundError(f"No model for detector {detector} under {base}")
        return cls.load(max(versions))

    def _raw(self, scaled_row: list[float]) -> float:
        # sklearn's score_samples is the opposite of the paper's anomaly score.
        return float(-self.model.score_samples([scaled_row])[0])

    def to_score01(self, raw: float) -> float:
        """Piecewise-linear rescale: raw_ref -> 0.5, raw_thr -> 0.9, 1.0 -> 1.0."""
        ref, thr = self.raw_ref, self.raw_thr
        if raw <= ref:
            return max(0.0, 0.5 * raw / ref) if ref > 0 else 0.0
        if raw <= thr:
            return 0.5 + 0.4 * (raw - ref) / (thr - ref)
        return min(1.0, 0.9 + 0.1 * (raw - thr) / max(1.0 - thr, 1e-9))

    def score(self, vector: dict[str, float]) -> tuple[float, list[str]]:
        """Return (score01, top_features) for one feature vector."""
        row = transform_row(vector)
        scaled = self.scaler.transform([row])[0]
        score01 = self.to_score01(self._raw(list(scaled)))

        # Top features: largest positive deviation from the training median,
        # in robust-scaled units.
        deviations = sorted(
            range(len(FEATURE_NAMES)),
            key=lambda i: scaled[i] - self._median[i],
            reverse=True,
        )
        top = [FEATURE_NAMES[i] for i in deviations[:3]]
        return score01, top
