"""Source interface."""

from __future__ import annotations

from typing import Iterator, Protocol

from ..schema import Record


class Source(Protocol):
    def backfill(self, now: float, history_s: int) -> list[Record]:
        """Records from the last `history_s` seconds, for a warm start."""
        ...

    def poll(self) -> Iterator[list[Record]]:
        """Yield batches of new records as they arrive (live), or a replay stream."""
        ...
