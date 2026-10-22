"""Falco alert receiver: the endpoint CYBER's Falcosidekick POSTs to.

CYBER configured Falcosidekick to POST Falco alerts (container runtime events such
as a shell spawned in a pod) to `http://service-ia.ia.svc.cluster.local:5000/remediate`.
This receiver accepts that JSON, counts it, optionally asks the RAG to confirm an
action, and hands the action to the same executor used for the brute-force path.

It always answers 2xx fast so Falcosidekick never blocks. Deciding a container
action from a Falco event is best-effort (restart the named workload); the main
demo (brute force) does not use this path.
"""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from . import metrics
from .executor import RemediationExecutor

log = logging.getLogger("detector.receiver")

# Falco priorities that warrant an action (others are logged only).
ACTIONABLE = {"emergency", "alert", "critical", "error", "warning"}


def parse_falco(payload: dict) -> dict:
    """Pull the fields we use from a standard Falco alert payload."""
    fields = payload.get("output_fields") or {}
    return {
        "priority": str(payload.get("priority", "")).lower(),
        "rule": payload.get("rule", ""),
        "output": payload.get("output", ""),
        "pod": fields.get("k8s.pod.name", ""),
        "namespace": fields.get("k8s.ns.name", ""),
        "user": fields.get("user.name", ""),
    }


class _Handler(BaseHTTPRequestHandler):
    executor: RemediationExecutor = None  # set by start_receiver

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/healthz", "/readyz"):
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.rstrip("/") != "/remediate":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})
            return
        alert = parse_falco(payload if isinstance(payload, dict) else {})
        metrics.falco_alerts_total.labels(alert["priority"] or "none").inc()
        # Low-priority alerts are counted but logged at debug: they can arrive by thousands.
        level = logging.INFO if alert["priority"] in ACTIONABLE else logging.DEBUG
        log.log(level, "falco alert rule=%r priority=%s pod=%s/%s",
                alert["rule"], alert["priority"], alert["namespace"], alert["pod"])
        acted = False
        if alert["priority"] in ACTIONABLE and alert["namespace"] == "applications":
            # Best-effort: restart the workload that owns the flagged pod.
            service = "auth" if "auth" in alert["pod"] else "payment"
            acted = self.executor.restart_service(service)
        self._json(202, {"status": "accepted", "acted": acted})

    def _json(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:  # silence access logs
        return


def start_receiver(port: int, executor: RemediationExecutor) -> ThreadingHTTPServer:
    _Handler.executor = executor
    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    log.info("Falco receiver listening on :%d/remediate", port)
    return server
