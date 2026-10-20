"""Postgres source: read DEV's `login_attempts` table live.

Polls rows newer than the last seen timestamp, with an overlap to catch late
inserts; duplicates are removed by row id. Requires a read-only DB user.
psycopg is an optional dependency, imported lazily so the file source works
without it.

Time zones: Prisma creates "createdAt" as timestamp(3) WITHOUT time zone and
writes UTC into it. So the session is forced to UTC and the filter is sent as a
naive UTC datetime: no implicit conversion can shift the reading window. If rows
still look ahead of the detector's clock, a warning is logged once, because the
detector would then see no recent rows and detect nothing.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime

from ..schema import Record, record_from_login_attempt

log = logging.getLogger("detector.postgres")

_QUERY = """
    SELECT id, "createdAt", "ipAddress", "attemptedEmail",
           "isAuthenticated", "failureReason", "targetUserId", "userAgent"
    FROM login_attempts
    WHERE "createdAt" > %(since)s
    ORDER BY "createdAt" ASC
    LIMIT %(limit)s
"""

# Rows more than this far ahead of our clock mean createdAt is not in UTC.
CLOCK_SKEW_WARN_S = 60.0


def naive_utc(epoch: float) -> datetime:
    """Unix seconds -> naive datetime holding UTC wall time (matches the column type)."""
    return datetime.fromtimestamp(epoch, tz=UTC).replace(tzinfo=None)


class PostgresSource:
    def __init__(
        self, dsn: str, overlap_s: int = 10, limit: int = 20000,
        connect: Callable | None = None,
    ) -> None:
        if connect is None:
            import psycopg  # lazy: only needed for the live source

            connect = psycopg.connect
        self._connect = connect
        self._dsn = dsn
        self._overlap_s = overlap_s
        self._limit = limit
        self._seen_ids: set[str] = set()
        self._skew_warned = False

    def _fetch(self, since_epoch: float) -> list[Record]:
        out: list[Record] = []
        with (
            self._connect(self._dsn, options="-c timezone=UTC") as conn,
            conn.cursor() as cur,
        ):
            cur.execute(_QUERY, {"since": naive_utc(since_epoch), "limit": self._limit})
            cols = [c.name for c in cur.description]
            for row in cur.fetchall():
                d = dict(zip(cols, row, strict=True))
                rid = str(d.get("id"))
                if rid in self._seen_ids:
                    continue
                self._seen_ids.add(rid)
                out.append(record_from_login_attempt(d))
        self._check_clock(out)
        return out

    def _check_clock(self, records: list[Record]) -> None:
        if self._skew_warned or not records:
            return
        ahead = max(r.ts for r in records) - time.time()
        if ahead > CLOCK_SKEW_WARN_S:
            self._skew_warned = True
            log.warning(
                "login_attempts rows are %.0f s ahead of the detector clock: createdAt is "
                "probably not written in UTC, so recent rows fall outside the windows",
                ahead,
            )

    def backfill(self, now: float, history_s: int) -> list[Record]:
        recs = self._fetch(now - history_s)
        recs.sort(key=lambda r: r.ts)
        return recs

    def poll_since(self, last_ts: float) -> list[Record]:
        recs = self._fetch(last_ts - self._overlap_s)
        recs.sort(key=lambda r: r.ts)
        # Bound the dedupe set so it cannot grow without limit.
        if len(self._seen_ids) > 200_000:
            self._seen_ids.clear()
        return recs
