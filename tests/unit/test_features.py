"""Feature computation sanity checks."""

from detector.features import FEATURE_NAMES, compute_vectors, transform_row
from detector.schema import Record


def _rec(ts, ip, user, result, reason=None, ua="ua"):
    return Record(ts=ts, src_ip=ip, username=user, result=result, reason=reason, user_agent=ua)


def test_feature_names_unique_and_ordered():
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))
    assert "n_fail_60s" in FEATURE_NAMES
    assert "g_top_ip_share" in FEATURE_NAMES


def test_brute_force_ip_has_high_fail_count():
    now = 1000.0
    records = [_rec(now - i * 0.2, "203.0.113.9", "a@x", "fail", "invalid") for i in range(100)]
    records.append(_rec(now - 1, "198.51.100.2", "b@x", "success"))
    vectors = compute_vectors(records, now)
    attacker = vectors["203.0.113.9"]
    assert attacker["n_fail_60s"] > 50
    assert attacker["fail_ratio_60s"] == 1.0
    assert attacker["g_top_ip_share"] > 0.9


def test_transform_row_length_matches_feature_names():
    now = 10.0
    vectors = compute_vectors([_rec(now, "203.0.113.1", "u", "fail", "invalid")], now)
    row = transform_row(next(iter(vectors.values())))
    assert len(row) == len(FEATURE_NAMES)


def test_ip_with_no_recent_events_produces_no_vector():
    now = 1000.0
    old = [_rec(now - 500, "203.0.113.5", "u", "fail")]
    assert compute_vectors(old, now) == {}
