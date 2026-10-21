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


# failureReason values written by DEV's auth service (epsi_pay auth/src/service.ts),
# mapped to the detector's reason names. The 5th wrong password is BRUTE_FORCE_LOCKED,
# later attempts on a locked account are ACCOUNT_LOCKED (LOCKED_USER: old dictionary name).
_REASONS = {
    "USER_NOT_FOUND": "unknown_user",
    "INVALID_CREDENTIALS": "invalid_credentials",
    "BRUTE_FORCE_LOCKED": "account_locked",
    "ACCOUNT_LOCKED": "account_locked",
    "LOCKED_USER": "account_locked",
    "IP_BLOCKED": "ip_blocked",
}


def normalize_ip(value: object) -> str:
    """Trim the address and turn IPv4-mapped IPv6 (::ffff:1.2.3.4) into plain IPv4.

    In-cluster callers can be recorded as ::ffff:10.42.x.y while the same host behind
    the gateway is plain IPv4; one host must not be split into two keys.
    """
    ip = str(value or "").strip()
    if ip.lower().startswith("::ffff:") and "." in ip:
        ip = ip[7:]
    return ip


def _reason(is_auth: bool, raw_reason: object, target_user: object) -> str | None:
    """Prefer the explicit failureReason; fall back to "no account" when it is missing.

    IP_BLOCKED rows have targetUserId NULL even for real accounts (the IP check runs
    before the user lookup), so a NULL targetUserId alone must not mean unknown user.
    """
    if is_auth:
        return None
    if raw_reason:
        code = str(raw_reason).strip().upper()
        return _REASONS.get(code, code.lower())
    if target_user in (None, "", "null"):
        return "unknown_user"
    return None


def record_from_login_attempt(row: dict) -> Record:
    """Map a `login_attempts` row (or a synthetic line in that shape) to a Record.

    Expected keys (DEV schema): createdAt, ipAddress, attemptedEmail,
    isAuthenticated, failureReason, targetUserId, userAgent.
    """
    ts = _parse_ts(row.get("createdAt") or row.get("ts"))
    is_auth = bool(row.get("isAuthenticated"))
    result = "success" if is_auth else "fail"
    reason = _reason(is_auth, row.get("failureReason"), row.get("targetUserId"))

    return Record(
        ts=ts,
        src_ip=normalize_ip(row.get("ipAddress") or row.get("src_ip")),
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
