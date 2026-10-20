"""Runtime configuration from environment variables (docs/interface-contract.md §7)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _split(value: str) -> list[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


@dataclass
class Config:
    source: str = "file"
    source_files: list[str] = field(default_factory=list)
    pg_dsn: str = ""
    pg_poll_overlap_s: int = 10

    sink: str = "stdout"
    remediation_url: str = ""
    remediation_token: str = ""

    enabled_detectors: list[str] = field(default_factory=lambda: ["auth_bruteforce"])
    models_dir: str = "models"
    cooldown_s: float = 300.0
    event_rate_cap_per_min: int = 10
    protected_ips: list[str] = field(default_factory=list)
    metrics_port: int = 9108
    tick_s: float = 5.0
    log_level: str = "info"
    replay: bool = False

    rag_enabled: bool = False
    ollama_url: str = "http://ollama.ia.svc.cluster.local:11434"
    rag_model: str = "llama3.1:8b"
    rag_timeout_s: float = 9.0

    @classmethod
    def from_env(cls) -> Config:
        e = os.environ
        return cls(
            source=e.get("SOURCE", "file"),
            source_files=_split(e.get("SOURCE_FILES", "")),
            pg_dsn=e.get("PG_DSN", ""),
            pg_poll_overlap_s=int(e.get("PG_POLL_OVERLAP_S", "10")),
            sink=e.get("SINK", "stdout"),
            remediation_url=e.get("REMEDIATION_URL", ""),
            remediation_token=e.get("REMEDIATION_TOKEN", ""),
            enabled_detectors=_split(e.get("ENABLED_DETECTORS", "auth_bruteforce")),
            models_dir=e.get("MODELS_DIR", "models"),
            cooldown_s=float(e.get("COOLDOWN_S", "300")),
            event_rate_cap_per_min=int(e.get("EVENT_RATE_CAP_PER_MIN", "10")),
            protected_ips=_split(e.get("PROTECTED_IPS", "")),
            metrics_port=int(e.get("METRICS_PORT", "9108")),
            tick_s=float(e.get("TICK_S", "5")),
            log_level=e.get("LOG_LEVEL", "info"),
            replay=e.get("REPLAY", "").lower() in ("1", "true", "yes"),
            rag_enabled=e.get("RAG_ENABLED", "").lower() in ("1", "true", "yes"),
            ollama_url=e.get("OLLAMA_URL", "http://ollama.ia.svc.cluster.local:11434"),
            rag_model=e.get("RAG_MODEL", "llama3.1:8b"),
            rag_timeout_s=float(e.get("RAG_TIMEOUT_S", "9")),
        )
