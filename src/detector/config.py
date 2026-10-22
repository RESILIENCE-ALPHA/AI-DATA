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
    score_threshold: float = 0.0  # 0 = use the model's own threshold (metadata.json)
    event_rate_cap_per_min: int = 10
    protected_ips: list[str] = field(default_factory=list)
    metrics_port: int = 9108
    tick_s: float = 5.0
    log_level: str = "info"
    replay: bool = False

    rag_enabled: bool = False
    ollama_url: str = "http://ollama.ia.svc.cluster.local:11434"
    rag_model: str = "mistral:7b"
    rag_timeout_s: float = 9.0
    rag_docs_dir: str = "runbooks"
    rag_embed_model: str = "nomic-embed-text"

    # Remediation executor (SINK=remediate). dry_run changes nothing on the cluster.
    remediation_mode: str = "dry_run"  # "dry_run" | "apisix"
    apisix_admin_url: str = "http://apisix-admin.apisix.svc.cluster.local:9180/apisix/admin"
    apisix_admin_key: str = ""
    apisix_global_rule_id: str = "ia-ipblock"
    block_ttl_s: float = 900.0
    restart_enabled: bool = False
    kubectl_bin: str = "kubectl"
    # Falco receiver (CYBER's Falcosidekick POSTs here).
    receiver_enabled: bool = False
    receiver_port: int = 5000

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
            score_threshold=float(e.get("SCORE_THRESHOLD", "0") or 0),
            event_rate_cap_per_min=int(e.get("EVENT_RATE_CAP_PER_MIN", "10")),
            protected_ips=_split(e.get("PROTECTED_IPS", "")),
            metrics_port=int(e.get("METRICS_PORT", "9108")),
            tick_s=float(e.get("TICK_S", "5")),
            log_level=e.get("LOG_LEVEL", "info"),
            replay=e.get("REPLAY", "").lower() in ("1", "true", "yes"),
            rag_enabled=e.get("RAG_ENABLED", "").lower() in ("1", "true", "yes"),
            ollama_url=e.get("OLLAMA_URL", "http://ollama.ia.svc.cluster.local:11434"),
            rag_model=e.get("RAG_MODEL", "mistral:7b"),
            rag_timeout_s=float(e.get("RAG_TIMEOUT_S", "9")),
            rag_docs_dir=e.get("RAG_DOCS_DIR", "runbooks"),
            rag_embed_model=e.get("RAG_EMBED_MODEL", "nomic-embed-text"),
            remediation_mode=e.get("REMEDIATION_MODE", "dry_run"),
            apisix_admin_url=e.get(
                "APISIX_ADMIN_URL",
                "http://apisix-admin.apisix.svc.cluster.local:9180/apisix/admin",
            ),
            apisix_admin_key=e.get("APISIX_ADMIN_KEY", ""),
            apisix_global_rule_id=e.get("APISIX_GLOBAL_RULE_ID", "ia-ipblock"),
            block_ttl_s=float(e.get("BLOCK_TTL_S", "900")),
            restart_enabled=e.get("RESTART_ENABLED", "").lower() in ("1", "true", "yes"),
            kubectl_bin=e.get("KUBECTL_BIN", "kubectl"),
            receiver_enabled=e.get("RECEIVER_ENABLED", "").lower() in ("1", "true", "yes"),
            receiver_port=int(e.get("RECEIVER_PORT", "5000")),
        )
