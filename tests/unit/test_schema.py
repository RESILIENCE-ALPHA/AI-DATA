"""login_attempts -> Record mapping."""

from detector.schema import record_from_login_attempt


def test_unknown_user_when_target_null_and_failed():
    # DEV's auth writes an unknown email as USER_NOT_FOUND with no account id.
    row = {
        "createdAt": "2026-10-20T14:02:00.000Z",
        "ipAddress": "203.0.113.9",
        "attemptedEmail": "ghost@x.fr",
        "isAuthenticated": False,
        "failureReason": "USER_NOT_FOUND",
        "targetUserId": None,
    }
    rec = record_from_login_attempt(row)
    assert rec.result == "fail"
    assert rec.reason == "unknown_user"


def test_fallback_unknown_user_when_no_reason_and_no_target():
    row = {"createdAt": "2026-10-20T14:02:00Z", "ipAddress": "203.0.113.9",
           "attemptedEmail": "ghost@x.fr", "isAuthenticated": False,
           "failureReason": None, "targetUserId": None}
    assert record_from_login_attempt(row).reason == "unknown_user"


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


def _failed(reason, target):
    return {"createdAt": "2026-10-21T10:00:00Z", "ipAddress": "203.0.113.9",
            "attemptedEmail": "alice@epsi.fr", "isAuthenticated": False,
            "failureReason": reason, "targetUserId": target}


def test_dev_reason_codes_mapped():
    assert record_from_login_attempt(_failed("USER_NOT_FOUND", None)).reason == "unknown_user"
    assert record_from_login_attempt(_failed("INVALID_CREDENTIALS", "u1")).reason == (
        "invalid_credentials")
    assert record_from_login_attempt(_failed("BRUTE_FORCE_LOCKED", "u1")).reason == (
        "account_locked")
    assert record_from_login_attempt(_failed("ACCOUNT_LOCKED", "u1")).reason == "account_locked"


def test_master_invalid_credentials_on_unknown_email_is_unknown_user():
    # Deployed auth (epsi_pay master) writes INVALID_CREDENTIALS + NULL target for an unknown email.
    assert record_from_login_attempt(_failed("INVALID_CREDENTIALS", None)).reason == "unknown_user"


def test_ip_blocked_with_null_target_is_not_unknown_user():
    # DEV writes IP_BLOCKED rows without targetUserId, even for real accounts.
    assert record_from_login_attempt(_failed("IP_BLOCKED", None)).reason == "ip_blocked"


def test_ipv4_mapped_ipv6_is_normalized():
    row = _failed("INVALID_CREDENTIALS", "u1") | {"ipAddress": " ::ffff:10.42.0.17 "}
    assert record_from_login_attempt(row).src_ip == "10.42.0.17"


def test_epoch_timestamp_accepted():
    row = {"ts": 1_700_000_000, "ipAddress": "203.0.113.1", "attemptedEmail": "a",
           "isAuthenticated": False, "targetUserId": "u"}
    rec = record_from_login_attempt(row)
    assert rec.ts == 1_700_000_000.0
