"""Remediation executor: block an attacker IP in APISIX, restart a workload.

Since CYBER exposes no remediation engine and wired Falco -> our service, the IA
service also EXECUTES the remediation (team decision, 22 Oct). The main demo path
is: our ML flags a brute-force IP -> `block_ip` here -> APISIX returns 403 to that
IP. A TTL lifts the block automatically (no human action), and protected IPs are
never blocked.

Blocking uses the APISIX Admin API global_rules endpoint with the `ip-restriction`
plugin (one global rule holds the whole blacklist):

    PUT  {admin}/global_rules/{id}   {"plugins": {"ip-restriction": {"blacklist": [...]}}}
    DELETE {admin}/global_rules/{id}  (when the blacklist becomes empty)

`mode="dry_run"` (the default) changes nothing on the cluster: it only logs and
counts, so a misconfigured key can never break the gateway. Set `mode="apisix"`
once the admin key is in place.
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import threading
from dataclasses import dataclass, field

from . import metrics

log = logging.getLogger("detector.executor")

DEFAULT_ADMIN_URL = "http://apisix-admin.apisix.svc.cluster.local:9180/apisix/admin"
DEFAULT_GLOBAL_RULE_ID = "ia-ipblock"


def _parse_nets(items: list[str]) -> list:
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


class ApisixBlocker:
    """Maintain one APISIX global rule whose ip-restriction blacklist is the block set."""

    def __init__(
        self, admin_url: str, admin_key: str, rule_id: str = DEFAULT_GLOBAL_RULE_ID,
        timeout_s: float = 5.0, client=None,
    ) -> None:
        self._base = admin_url.rstrip("/") + f"/global_rules/{rule_id}"
        self._headers = {"X-API-KEY": admin_key, "Content-Type": "application/json"}
        self._timeout = timeout_s
        self._client = client  # injectable for tests; else httpx created lazily

    def _request(self, method: str, json=None):
        if self._client is not None:
            return self._client.request(method, self._base, headers=self._headers, json=json)
        import httpx

        return httpx.request(
            method, self._base, headers=self._headers, json=json, timeout=self._timeout
        )

    def sync(self, blacklist: list[str]) -> None:
        """Push the current blacklist to APISIX (delete the rule when empty)."""
        if blacklist:
            body = {"plugins": {"ip-restriction": {"blacklist": sorted(blacklist),
                                                   "message": "blocked by IA remediation"}}}
            resp = self._request("PUT", json=body)
        else:
            resp = self._request("DELETE")
        status = getattr(resp, "status_code", 0)
        if not (200 <= status < 300) and not (status == 404 and not blacklist):
            raise RuntimeError(f"APISIX admin returned {status}")


@dataclass
class RemediationExecutor:
    protected_ips: list[str] = field(default_factory=list)
    block_ttl_s: float = 900.0  # 15 min, matches CYBER's TTL
    mode: str = "dry_run"  # "dry_run" | "apisix"
    blocker: ApisixBlocker | None = None
    restart_enabled: bool = False
    kubectl_bin: str = "kubectl"
    restart_map: dict[str, str] | None = None  # service -> "namespace/deployment"

    def __post_init__(self) -> None:
        self._nets = _parse_nets(self.protected_ips)
        self._blocked_until: dict[str, float] = {}
        self._lock = threading.Lock()
        self._restart_map = self.restart_map or {
            "auth": "applications/epsi-pay-auth",
            "api": "applications/epsi-pay-auth",
            "payment": "applications/epsi-pay-payment",
        }

    def is_protected(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # a non-IP string is never blocked
        return any(addr in n for n in self._nets)

    @property
    def blocked_ips(self) -> list[str]:
        with self._lock:
            return sorted(self._blocked_until)

    def block_ip(self, ip: str, now: float, reason: str = "") -> bool:
        """Block `ip` until now + TTL. Returns True if a new block was applied."""
        if self.is_protected(ip):
            metrics.remediation_protected_skips_total.inc()
            log.warning("refused to block protected or invalid IP %s", ip)
            return False
        with self._lock:
            fresh = ip not in self._blocked_until
            self._blocked_until[ip] = now + self.block_ttl_s
            current = list(self._blocked_until)
        if fresh:
            self._apply(current, action="block", ip=ip, reason=reason)
            metrics.remediation_blocks_total.inc()
        metrics.currently_blocked_ips.set(len(current))
        return fresh

    def unblock_ip(self, ip: str) -> None:
        with self._lock:
            if ip not in self._blocked_until:
                return
            del self._blocked_until[ip]
            current = list(self._blocked_until)
        self._apply(current, action="unblock", ip=ip)
        metrics.remediation_unblocks_total.inc()
        metrics.currently_blocked_ips.set(len(current))

    def sweep(self, now: float) -> None:
        """Lift every block whose TTL has passed (called each detector tick)."""
        with self._lock:
            expired = [ip for ip, until in self._blocked_until.items() if until <= now]
        for ip in expired:
            log.info("TTL expired, unblocking %s", ip)
            self.unblock_ip(ip)

    def _apply(self, blacklist: list[str], action: str, ip: str, reason: str = "") -> None:
        log.info("%s %s (%s) -> blacklist size %d [mode=%s]",
                 action, ip, reason, len(blacklist), self.mode)
        if self.mode != "apisix" or self.blocker is None:
            return
        try:
            self.blocker.sync(blacklist)
        except Exception as exc:  # noqa: BLE001 - must not crash the loop
            metrics.remediation_errors_total.inc()
            log.error("APISIX %s of %s failed: %s", action, ip, exc)

    def restart_service(self, service: str) -> bool:
        """Restart the workload behind `service` (bonus path). Guarded and best-effort."""
        target = self._restart_map.get(service)
        if not target:
            log.warning("no restart target mapped for service %r", service)
            return False
        ns, _, deploy = target.partition("/")
        log.info("restart_service %s -> %s/%s [enabled=%s mode=%s]",
                 service, ns, deploy, self.restart_enabled, self.mode)
        if not self.restart_enabled or self.mode != "apisix":
            return False
        try:
            subprocess.run(  # noqa: S603 - fixed args, no shell
                [self.kubectl_bin, "-n", ns, "rollout", "restart", f"deployment/{deploy}"],
                check=True, capture_output=True, timeout=30,
            )
            metrics.remediation_restarts_total.inc()
            return True
        except Exception as exc:  # noqa: BLE001
            metrics.remediation_errors_total.inc()
            log.error("restart of %s failed: %s", target, exc)
            return False
