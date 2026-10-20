"""Decision logic: confirmation, cooldown, protected IPs, severity."""

from detector.decision import Engine


def _engine(**kw):
    return Engine(detector="auth_bruteforce", model_version="0.1.0", threshold=0.9, **kw)


def test_requires_two_consecutive_ticks():
    eng = _engine()
    out = eng.update("203.0.113.9", 0.95, ["n_fail_60s"], {}, now=100.0)
    assert out.event is None and out.low is True
    out = eng.update("203.0.113.9", 0.96, ["n_fail_60s"], {}, now=105.0)
    assert out.event is not None
    assert out.event.severity == "medium"


def test_high_severity_above_097():
    eng = _engine()
    eng.update("203.0.113.9", 0.98, [], {}, now=100.0)
    out = eng.update("203.0.113.9", 0.99, [], {}, now=105.0)
    assert out.event.severity == "high"


def test_cooldown_blocks_second_event():
    eng = _engine(cooldown_s=300)
    eng.update("203.0.113.9", 0.98, [], {}, now=100.0)
    first = eng.update("203.0.113.9", 0.98, [], {}, now=105.0)
    assert first.event is not None
    second = eng.update("203.0.113.9", 0.98, [], {}, now=110.0)
    assert second.event is None


def test_protected_ip_never_fires():
    eng = _engine(protected_ips=["203.0.113.0/24"])
    eng.update("203.0.113.9", 0.99, [], {}, now=100.0)
    out = eng.update("203.0.113.9", 0.99, [], {}, now=105.0)
    assert out.event is None
    assert out.protected_hit is True


def test_score_below_threshold_resets():
    eng = _engine()
    eng.update("203.0.113.9", 0.95, [], {}, now=100.0)
    eng.update("203.0.113.9", 0.10, [], {}, now=105.0)
    out = eng.update("203.0.113.9", 0.95, [], {}, now=110.0)
    assert out.event is None and out.low is True
