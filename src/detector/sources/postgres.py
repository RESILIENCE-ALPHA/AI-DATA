"""Postgres source: read DEV's `login_attempts` table live.

Polls rows newer than the last seen timestamp, with an overlap to catch late
inserts; duplicates are removed by row id. Requires a read-only DB user.
psycopg is an optional dependency, imported lazily so the file source works
without it.
"""

from __future__ import annotations

from datetime import UTC

from ..schema import Record, record_from_login_attempt

_QUERY = """
    SELECT id, "createdAt", "ipAddress", "attemptedEmail",
           "isAuthenticated", "failureReason", "targetUserId", "userAgent"
    FROM login_attempts
    WHERE "createdAt" > %(since)s
    ORDER BY "createdAt" ASC
    LIMIT %(limit)s
"""


class PostgresSource:
    def __init__(self, dsn: str, overlap_s: int = 10, limit: int = 20000) -> None:
        import psycopg  # lazy: only needed for the live source

        self._psycopg = psycopg
        self._dsn = dsn
        self._overlap_s = overlap_s
        self._limit = limit
        self._seen_ids: set[str] = set()

    def _fetch(self, since_epoch: float) -> list[Record]:
        from datetime import datetime

        since = datetime.fromtimestamp(since_epoch, tz=UTC)
        out: list[Record] = []
        with self._psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
            cur.execute(_QUERY, {"since": since, "limit": self._limit})
            cols = [c.name for c in cur.description]
            for row in cur.fetchall():
                d = dict(zip(cols, row, strict=True))
                rid = str(d.get("id"))
                if rid in self._seen_ids:
                    continue
                self._seen_ids.add(rid)
                out.append(record_from_login_attempt(d))
        return out

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
