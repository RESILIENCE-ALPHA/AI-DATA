"""Rolling buffer of the last HISTORY_S seconds of records, pruned by event time."""

from __future__ import annotations

from collections import deque

from .features import HISTORY_S
from .schema import Record


class RollingBuffer:
    """Keeps records whose ts is within HISTORY_S of the most recent event seen."""

    def __init__(self, history_s: int = HISTORY_S) -> None:
        self._history_s = history_s
        self._buf: deque[Record] = deque()
        self._latest_ts: float = 0.0

    def add(self, record: Record) -> None:
        self._buf.append(record)
        if record.ts > self._latest_ts:
            self._latest_ts = record.ts

    def add_many(self, records: list[Record]) -> None:
        for r in records:
            self.add(r)

    def prune(self, now: float) -> None:
        cutoff = now - self._history_s
        while self._buf and self._buf[0].ts < cutoff:
            self._buf.popleft()

    @property
    def records(self) -> list[Record]:
        return list(self._buf)

    @property
    def latest_ts(self) -> float:
        return self._latest_ts

    def __len__(self) -> int:
        return len(self._buf)
