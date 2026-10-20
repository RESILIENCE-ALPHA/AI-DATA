"""login_attempts -> Record mapping."""

from detector.schema import record_from_login_attempt


def test_unknown_user_when_target_null_and_failed():
    row = {
        "createdAt": "2026-10-20T14:02:00.000Z",
        "ipAddress": "203.0.113.9",
        "attemptedEmail": "ghost@x.fr",
        "isAuthenticated": False,
        "failureReason": "INVALID_CREDENTIALS",
        "targetUserId": None,
    }
    rec = record_from_login_attempt(row)
    assert rec.result == "fail"
    assert rec.reason == "unknown_user"


def test_success_maps_result():
    row = {
        "createdAt": "2026-10-20T14:02:00Z",
        "ipAddress": "198.51.100.2",
        "attemptedEmail": "alice@epsi.fr",
        "isAuthenticated": True,
        "targetUserId": "u1",
    }
    rec = record_from_login_attempt(row)
    assert rec.result == "success"
    assert rec.reason is None


def test_epoch_timestamp_accepted():
    row = {"ts": 1_700_000_000, "ipAddress": "203.0.113.1", "attemptedEmail": "a",
           "isAuthenticated": False, "targetUserId": "u"}
    rec = record_from_login_attempt(row)
    assert rec.ts == 1_700_000_000.0
