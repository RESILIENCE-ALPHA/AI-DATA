"""Prometheus metrics (subset of docs/interface-contract.md §6) and health server."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest

REGISTRY = CollectorRegistry()

anomaly_score = Gauge(
    "detector_anomaly_score", "Latest score per IP", ["detector", "src_ip"], registry=REGISTRY
)
alerts_total = Counter(
    "detector_alerts_total", "Events sent", ["detector", "severity"], registry=REGISTRY
)
low_detections_total = Counter(
    "detector_low_detections_total", "Single-tick detections (not sent)", ["detector"],
    registry=REGISTRY,
)
vectors_scored_total = Counter(
    "detector_vectors_scored_total", "Vectors scored", ["detector"], registry=REGISTRY
)
rejected_lines_total = Counter(
    "detector_rejected_lines_total", "Malformed source rows dropped", registry=REGISTRY
)
source_errors_total = Counter(
    "detector_source_errors_total", "Source read errors", registry=REGISTRY
)
sink_errors_total = Counter(
    "detector_sink_errors_total", "Events not delivered after retries", registry=REGISTRY
)
protected_ip_hits_total = Counter(
    "detector_protected_ip_hits_total", "Protected IPs that would have fired", ["detector"],
    registry=REGISTRY,
)
events_capped_total = Counter(
    "detector_events_capped_total", "Events suppressed by the global cap", registry=REGISTRY
)
model_info = Gauge(
    "detector_model_info", "Model and release live", ["detector", "model_version"],
    registry=REGISTRY,
)
last_alert_timestamp = Gauge(
    "detector_last_alert_timestamp_seconds", "Unix time of the last event sent",
    ["detector"], registry=REGISTRY,
)

_READY = {"ready": False}


def set_ready(value: bool) -> None:
    _READY["ready"] = value


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/metrics":
            body = generate_latest(REGISTRY)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/healthz":
            self._text(200, "ok")
        elif self.path == "/readyz":
            self._text(200 if _READY["ready"] else 503, "ready" if _READY["ready"] else "not ready")
        else:
            self._text(404, "not found")

    def _text(self, code: int, msg: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(msg.encode())

    def log_message(self, *args) -> None:  # silence access logs
        return


def start_metrics_server(port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server
