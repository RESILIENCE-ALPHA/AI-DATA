"""HTTP sink: POST the anomaly event to the CYBER remediation endpoint.

Retries 3 times with backoff; the event_id is the idempotency key, so a retry
the receiver already processed is safe. Mirrors every event to stdout too.
"""

from __future__ import annotations

import time

import httpx

from ..metrics import sink_errors_total
from ..schema import AnomalyEvent
from .stdout import StdoutSink


class HttpSink:
    def __init__(self, url: str, token: str = "", timeout_s: float = 5.0) -> None:
        self._url = url.rstrip("/") + "/remediate"
        self._headers = {"Content-Type": "application/json"}
        if token:
            self._headers["Authorization"] = f"Bearer {token}"
        self._timeout = timeout_s
        self._mirror = StdoutSink()

    def send(self, event: AnomalyEvent) -> bool:
        self._mirror.send(event)
        body = event.model_dump_json()
        for attempt in range(3):
            try:
                resp = httpx.post(
                    self._url, content=body, headers=self._headers, timeout=self._timeout
                )
                if 200 <= resp.status_code < 300:
                    return True
            except httpx.HTTPError:
                pass
            time.sleep(0.5 * (attempt + 1))
        sink_errors_total.inc()
        return False
