"""Records and events: the contract objects the detector reads and emits.

A `Record` is one normalised login attempt. It is produced either from a
`login_attempts` row (live Postgres source, DEV's table) or from a synthetic
JSON line in the same shape (file source, tests, replay). Both paths go through
`record_from_login_attempt` so there is a single mapping, matching
`CLAUDE.md` > "Data source" and `docs/interface-contract.md` §2.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import BaseModel, Field


@dataclass(slots=True)
class Record:
    """One normalised login attempt, as the feature code consumes it."""

    ts: float  # unix seconds, UTC
    src_ip: str
    username: str
    result: str  # "success" | "fail"
    reason: str | None  # e.g. "unknown_user", "invalid_credentials", "account_locked"
    user_agent: str | None


def _parse_ts(value: object) -> float:
    """Accept an ISO-8601 string (with or without trailing Z) or a unix number."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.timestamp()
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()


def record_from_login_attempt(row: dict) -> Record:
    """Map a `login_attempts` row (or a synthetic line in that shape) to a Record.

    Expected keys (DEV schema): createdAt, ipAddress, attemptedEmail,
    isAuthenticated, failureReason, targetUserId, userAgent.
    """
    ts = _parse_ts(row.get("createdAt") or row.get("ts"))
    is_auth = bool(row.get("isAuthenticated"))
    result = "success" if is_auth else "fail"

    raw_reason = row.get("failureReason")
    target_user = row.get("targetUserId")
    if not is_auth and target_user in (None, "", "null"):
        reason = "unknown_user"
    elif raw_reason:
        reason = str(raw_reason).lower()
    else:
        reason = None

    return Record(
        ts=ts,
        src_ip=str(row.get("ipAddress") or row.get("src_ip") or ""),
        username=str(row.get("attemptedEmail") or row.get("username") or ""),
        result=result,
        reason=reason,
        user_agent=row.get("userAgent") or row.get("user_agent"),
    )


class Evidence(BaseModel):
    """Key feature values plus the top contributing features, for the dashboard."""

    n_fail_60s: float = 0.0
    n_success_60s: float = 0.0
    n_distinct_users_60s: float = 0.0
    req_per_s_60s: float = 0.0
    top_features: list[str] = Field(default_factory=list)


class AnomalyEvent(BaseModel):
    """The JSON the detector POSTs to the CYBER remediation endpoint.

    See `docs/interface-contract.md` §5. The RAG fields (`rag_action`,
    `rag_explanation`) are added when the assistant runs inside the loop.
    """

    event_id: str
    ts: str
    detector: str
    model_version: str
    severity: str  # "medium" | "high"
    score: float
    src_ip: str
    target_service: str
    recommended_actions: list[str]
    evidence: Evidence
    rag_action: str | None = None
    rag_explanation: str | None = None
