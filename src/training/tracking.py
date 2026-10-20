"""MLflow helpers: one place for the tracking URI and experiment name.

Tracking is local by default (`sqlite:///mlflow.db` + `mlruns/` artifacts), so no
server is needed; set MLFLOW_TRACKING_URI to point at a shared MLflow server.
A SQL backend is required because the Model Registry does not work with the
plain file store. Browse runs with `make mlflow-ui`.
"""

from __future__ import annotations

import os

DEFAULT_TRACKING_URI = "sqlite:///mlflow.db"
PRODUCTION_ALIAS = "production"


def tracking_uri(override: str | None = None) -> str:
    return override or os.environ.get("MLFLOW_TRACKING_URI", DEFAULT_TRACKING_URI)


def setup(detector: str, override_uri: str | None = None):
    """Point MLflow at the tracking store and select the detector's experiment."""
    import mlflow

    mlflow.set_tracking_uri(tracking_uri(override_uri))
    mlflow.set_experiment(detector)
    return mlflow
