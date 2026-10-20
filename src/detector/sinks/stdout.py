"""Stdout sink: write each event as one JSON line.

Used in tests and replay, and always as a mirror in production so Loki keeps a
record the dashboard and the RAG assistant can read.
"""

from __future__ import annotations

from ..schema import AnomalyEvent


class StdoutSink:
    def send(self, event: AnomalyEvent) -> bool:
        print(event.model_dump_json(), flush=True)
        return True
