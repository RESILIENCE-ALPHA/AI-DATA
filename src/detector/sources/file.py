"""File source: read login_attempts-shaped JSON lines, for tests and replay.

In replay mode the service drives simulated time from the record timestamps, so a
one-hour capture is scored tick by tick without waiting an hour. `load_records`
is also used by the training feature builder.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..metrics import rejected_lines_total
from ..schema import Record, record_from_login_attempt


def load_records(paths: list[str]) -> list[Record]:
    records: list[Record] = []
    for p in paths:
        path = Path(p)
        if not path.exists():
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    records.append(record_from_login_attempt(row))
                except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                    rejected_lines_total.inc()
    records.sort(key=lambda r: r.ts)
    return records


class FileSource:
    def __init__(self, paths: list[str]) -> None:
        self._records = load_records(paths)

    def backfill(self, now: float, history_s: int) -> list[Record]:
        return [r for r in self._records if now - history_s < r.ts <= now]

    @property
    def records(self) -> list[Record]:
        return self._records
