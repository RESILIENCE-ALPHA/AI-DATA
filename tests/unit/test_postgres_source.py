"""Postgres source with a fake connection: UTC handling, mapping, dedupe, clock check.

The real table (Prisma) has "createdAt" as timestamp(3) WITHOUT time zone, written
in UTC, and psycopg returns such values as naive datetimes. The fake reproduces that.
"""

import logging
import time
from datetime import UTC, datetime

from detector.sources.postgres import PostgresSource, naive_utc

COLS = ["id", "createdAt", "ipAddress", "attemptedEmail", "isAuthenticated",
        "failureReason", "targetUserId", "userAgent"]


class _Col:
    def __init__(self, name):
        self.name = name


class _Cursor:
    def __init__(self, db):
        self.db = db
        self.description = [_Col(c) for c in COLS]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, query, params):
        self.db.last_params = params

    def fetchall(self):
        return list(self.db.rows)


class _Conn:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):
        return _Cursor(self.db)


class FakeDb:
    def __init__(self, rows):
        self.rows = rows
        self.last_params = None
        self.connect_kwargs = None

    def connect(self, dsn, **kwargs):
        self.connect_kwargs = kwargs
        return _Conn(self)


def _row(rid, epoch, ip, email, ok, reason, target):
    return (rid, naive_utc(epoch), ip, email, ok, reason, target, "Mozilla/5.0")


def test_session_forced_to_utc_and_since_is_naive_utc():
    db = FakeDb([])
    src = PostgresSource("postgresql://x", connect=db.connect)
    src.backfill(now=1_800_000_000.0, history_s=300)
    assert db.connect_kwargs == {"options": "-c timezone=UTC"}
    since = db.last_params["since"]
    assert since.tzinfo is None
    assert since == datetime.fromtimestamp(1_800_000_000.0 - 300, tz=UTC).replace(tzinfo=None)


def test_rows_mapped_with_confirmed_target_user_rule():
    now = time.time()
    ip, bad = "203.0.113.9", "INVALID_CREDENTIALS"
    db = FakeDb([
        _row("1", now - 30, ip, "alice@epsi.fr", True, None, "u-alice"),
        _row("2", now - 20, ip, "alice@epsi.fr", False, bad, "u-alice"),
        _row("3", now - 10, ip, "ghost@epsi.fr", False, "USER_NOT_FOUND", None),
    ])
    recs = PostgresSource("dsn", connect=db.connect).backfill(now, 300)
    assert [r.reason for r in recs] == [None, "invalid_credentials", "unknown_user"]
    assert [r.result for r in recs] == ["success", "fail", "fail"]
    assert abs(recs[2].ts - (now - 10)) < 0.01  # naive value read back as UTC


def test_overlap_rows_are_not_returned_twice():
    now = time.time()
    db = FakeDb([_row("1", now - 5, "203.0.113.9", "a@x", False, "INVALID_CREDENTIALS", "u")])
    src = PostgresSource("dsn", connect=db.connect)
    assert len(src.poll_since(now)) == 1
    assert src.poll_since(now) == []


def test_warns_once_when_rows_look_ahead_of_utc(caplog):
    two_hours_ahead = time.time() + 7200  # e.g. local Paris time stored as if UTC
    db = FakeDb([_row("1", two_hours_ahead, "203.0.113.9", "a@x", False, None, "u")])
    src = PostgresSource("dsn", connect=db.connect)
    with caplog.at_level(logging.WARNING, logger="detector.postgres"):
        src.poll_since(time.time())
        src.poll_since(time.time())
    warnings = [r for r in caplog.records if "ahead of the detector clock" in r.message]
    assert len(warnings) == 1
