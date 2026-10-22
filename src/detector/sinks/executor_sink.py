"""Executor sink: run the remediation for an anomaly event, in-process.

Used when IA owns execution (SINK=remediate). It mirrors the event to stdout (so
Loki keeps a record), then applies the action: `block_ip` blocks the source IP in
APISIX, `restart_service` restarts the target workload. The action set is the RAG
choice when present, else the event's recommended actions.
"""

from __future__ import annotations

import time

from ..executor import RemediationExecutor
from ..schema import AnomalyEvent
from .stdout import StdoutSink


class ExecutorSink:
    def __init__(self, executor: RemediationExecutor) -> None:
        self._executor = executor
        self._mirror = StdoutSink()

    def send(self, event: AnomalyEvent) -> bool:
        self._mirror.send(event)
        actions = [event.rag_action] if event.rag_action else list(event.recommended_actions)
        now = time.time()
        ok = True
        if "block_ip" in actions:
            ok = self._executor.block_ip(event.src_ip, now, reason=event.detector) or ok
        if "restart_service" in actions:
            self._executor.restart_service(event.target_service)
        return ok
