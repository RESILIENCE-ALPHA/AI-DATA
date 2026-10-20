"""Turn per-tick scores into anomaly events.

Rules (docs/model-spec.md §4):
- confirmation: score above threshold on 2 consecutive ticks,
- severity: high at score >= 0.97, else medium (single-tick = low, not sent),
- cooldown: no new event for the same IP for COOLDOWN_S,
- global cap: at most EVENT_RATE_CAP_PER_MIN events per minute,
- protected IPs: never flagged (IP or CIDR).
"""

from __future__ import annotations

import ipaddress
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .schema import AnomalyEvent, Evidence

HIGH_SEVERITY_SCORE = 0.97

# Default remediation per detector (the executor decides what it runs).
_DEFAULTS = {
    "auth_bruteforce": ("auth", ["block_ip", "restart_service"]),
    "api_flood": ("api", ["block_ip", "restart_service"]),
}


def _parse_protected(items: list[str]) -> list:
    nets = []
    for raw in items:
        s = raw.strip()
        if not s:
            continue
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            continue
    return nets


@dataclass
class DecisionOutcome:
    event: AnomalyEvent | None = None
    low: bool = False
    protected_hit: bool = False
    capped: bool = False


@dataclass
class Engine:
    detector: str
    model_version: str
    threshold: float
    cooldown_s: float = 300.0
    event_cap_per_min: int = 10
    protected_ips: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._above: dict[str, int] = {}
        self._cooldown_until: dict[str, float] = {}
        self._recent_events: deque[float] = deque()
        self._nets = _parse_protected(self.protected_ips)
        self._target, self._actions = _DEFAULTS.get(
            self.detector, ("auth", ["block_ip", "restart_service"])
        )

    def _is_protected(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self._nets)

    def _cap_ok(self, now: float) -> bool:
        while self._recent_events and self._recent_events[0] < now - 60:
            self._recent_events.popleft()
        return len(self._recent_events) < self.event_cap_per_min

    def update(
        self, src_ip: str, score: float, top_features: list[str], vector: dict, now: float
    ) -> DecisionOutcome:
        if score < self.threshold:
            self._above[src_ip] = 0
            return DecisionOutcome()

        self._above[src_ip] = self._above.get(src_ip, 0) + 1
        if self._above[src_ip] < 2:
            return DecisionOutcome(low=True)  # single tick: logged, not sent

        if self._is_protected(src_ip):
            return DecisionOutcome(protected_hit=True)

        if now < self._cooldown_until.get(src_ip, 0.0):
            return DecisionOutcome()

        if not self._cap_ok(now):
            return DecisionOutcome(capped=True)

        self._cooldown_until[src_ip] = now + self.cooldown_s
        self._recent_events.append(now)

        severity = "high" if score >= HIGH_SEVERITY_SCORE else "medium"
        evidence = Evidence(
            n_fail_60s=vector.get("n_fail_60s", 0.0),
            n_success_60s=vector.get("n_success_60s", 0.0),
            n_distinct_users_60s=vector.get("n_distinct_users_60s", 0.0),
            req_per_s_60s=vector.get("req_per_s_60s", 0.0),
            top_features=top_features,
        )
        event = AnomalyEvent(
            event_id=str(uuid.uuid4()),
            ts=datetime.fromtimestamp(now, tz=UTC).isoformat().replace("+00:00", "Z"),
            detector=self.detector,
            model_version=self.model_version,
            severity=severity,
            score=round(score, 4),
            src_ip=src_ip,
            target_service=self._target,
            recommended_actions=list(self._actions),
            evidence=evidence,
        )
        return DecisionOutcome(event=event)

    def seed_cooldown(self, src_ip: str, until: float) -> None:
        """Restore a cooldown after a restart (from the service's own past events)."""
        self._cooldown_until[src_ip] = max(self._cooldown_until.get(src_ip, 0.0), until)
