"""Remediation executor: APISIX block/unblock, TTL, protected IPs, dry-run safety."""

from detector.executor import ApisixBlocker, RemediationExecutor
from detector.schema import AnomalyEvent, Evidence
from detector.sinks.executor_sink import ExecutorSink


class FakeApisix:
    """Records the blacklist APISIX was told to hold."""

    def __init__(self):
        self.calls = []
        self.last_blacklist = None

    def request(self, method, url, headers=None, json=None):
        self.calls.append((method, json))
        if method == "PUT":
            self.last_blacklist = json["plugins"]["ip-restriction"]["blacklist"]
        elif method == "DELETE":
            self.last_blacklist = []
        return type("R", (), {"status_code": 200})()


def _executor(mode="apisix", protected=None, ttl=900.0):
    fake = FakeApisix()
    blocker = ApisixBlocker("http://admin/apisix/admin", "key", client=fake)
    ex = RemediationExecutor(
        protected_ips=protected or [], block_ttl_s=ttl, mode=mode, blocker=blocker,
    )
    return ex, fake


def test_block_adds_ip_to_apisix_blacklist():
    ex, fake = _executor()
    assert ex.block_ip("203.0.113.9", now=100.0) is True
    assert fake.last_blacklist == ["203.0.113.9"]
    assert ex.blocked_ips == ["203.0.113.9"]


def test_second_block_of_same_ip_is_not_reapplied():
    ex, fake = _executor()
    ex.block_ip("203.0.113.9", now=100.0)
    calls_before = len(fake.calls)
    assert ex.block_ip("203.0.113.9", now=120.0) is False
    assert len(fake.calls) == calls_before  # no extra APISIX call


def test_protected_ip_is_never_blocked():
    ex, fake = _executor(protected=["203.0.113.0/24"])
    assert ex.block_ip("203.0.113.9", now=100.0) is False
    assert fake.calls == []
    assert ex.blocked_ips == []


def test_ttl_sweep_unblocks_and_clears_rule():
    ex, fake = _executor(ttl=300.0)
    ex.block_ip("203.0.113.9", now=100.0)
    ex.sweep(now=200.0)  # not yet expired
    assert ex.blocked_ips == ["203.0.113.9"]
    ex.sweep(now=500.0)  # TTL passed
    assert ex.blocked_ips == []
    assert fake.last_blacklist == []  # rule deleted when empty


def test_two_ips_share_one_rule():
    ex, fake = _executor()
    ex.block_ip("203.0.113.9", now=100.0)
    ex.block_ip("198.51.100.7", now=101.0)
    assert fake.last_blacklist == ["198.51.100.7", "203.0.113.9"]  # sorted


def test_dry_run_changes_nothing_on_apisix():
    ex, fake = _executor(mode="dry_run")
    assert ex.block_ip("203.0.113.9", now=100.0) is True
    assert fake.calls == []  # tracked locally, no APISIX call
    assert ex.blocked_ips == ["203.0.113.9"]


def _event(ip="203.0.113.9", action=None):
    return AnomalyEvent(
        event_id="e1", ts="2026-10-22T10:00:00Z", detector="auth_bruteforce",
        model_version="0.1.0", severity="high", score=0.99, src_ip=ip,
        target_service="auth", recommended_actions=["block_ip", "restart_service"],
        evidence=Evidence(), rag_action=action,
    )


def test_executor_sink_blocks_the_event_ip():
    ex, fake = _executor()
    ExecutorSink(ex).send(_event())
    assert ex.blocked_ips == ["203.0.113.9"]


def test_executor_sink_follows_rag_action_block_only():
    ex, fake = _executor()
    ExecutorSink(ex).send(_event(action="block_ip"))
    assert ex.blocked_ips == ["203.0.113.9"]
