"""Load a trained model and score vectors to a 0..1 anomaly score.

Isolation Forest returns a raw anomaly value; we map it to 0..1 with an empirical
CDF of the training scores stored in metadata. A vector more anomalous than 90 %
of training traffic scores 0.90. The model's feature list must match the running
code, or loading fails (no train/serve skew).
"""

from __future__ import annotations

import json
import pickle
from bisect import bisect_right
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
        self._cdf = metadata["calibration_scores"]  # sorted raw anomaly scores
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
        return cls.load(sorted(versions)[-1])

    def _raw(self, scaled_row: list[float]) -> float:
        # Higher = more anomalous.
        return float(-self.model.score_samples([scaled_row])[0])

    def score(self, vector: dict[str, float]) -> tuple[float, list[str]]:
        """Return (score01, top_features) for one feature vector."""
        row = transform_row(vector)
        scaled = self.scaler.transform([row])[0]
        raw = self._raw(list(scaled))
        rank = bisect_right(self._cdf, raw)
        score01 = rank / max(len(self._cdf), 1)

        # Top features: largest positive deviation from the training median,
        # in robust-scaled units.
        deviations = sorted(
            range(len(FEATURE_NAMES)),
            key=lambda i: scaled[i] - self._median[i],
            reverse=True,
        )
        top = [FEATURE_NAMES[i] for i in deviations[:3]]
        return score01, top
