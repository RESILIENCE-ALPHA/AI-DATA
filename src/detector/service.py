"""Service loop: tie source, features, scorer, decision, RAG and sink together.

Two modes:
- replay (REPLAY=1): drive simulated time from the record timestamps in a file,
  score tick by tick as fast as possible. Used for tests, evaluation and a
  cluster-free demo.
- live (default): poll the source on wall-clock ticks of TICK_S seconds.

Both share the same scoring path, so replay results match live behaviour.
"""

from __future__ import annotations

import logging
import time

from . import metrics
from .config import Config
from .decision import Engine
from .scorer import Scorer
from .windowing import RollingBuffer

log = logging.getLogger("detector")


class Service:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.scorers: dict[str, Scorer] = {}
        self.engines: dict[str, Engine] = {}
        self.buffer = RollingBuffer()
        self.sink = self._build_sink()
        self.rag = self._build_rag()

    def _build_sink(self):
        if self.config.sink == "http" and self.config.remediation_url:
            from .sinks.http import HttpSink

            return HttpSink(self.config.remediation_url, self.config.remediation_token)
        from .sinks.stdout import StdoutSink

        return StdoutSink()

    def _build_rag(self):
        if not self.config.rag_enabled:
            return None
        from .rag import RagClient

        return RagClient(self.config.ollama_url, self.config.rag_model, self.config.rag_timeout_s)

    def load_models(self) -> None:
        for name in self.config.enabled_detectors:
            scorer = Scorer.load_production(self.config.models_dir, name)
            self.scorers[name] = scorer
            self.engines[name] = Engine(
                detector=name,
                model_version=scorer.model_version,
                threshold=scorer.threshold,
                cooldown_s=self.config.cooldown_s,
                event_cap_per_min=self.config.event_rate_cap_per_min,
                protected_ips=self.config.protected_ips,
            )
            metrics.model_info.labels(name, scorer.model_version).set(1)
        log.info("loaded detectors: %s", ", ".join(self.scorers))

    def score_tick(self, now: float) -> None:
        from .features import compute_vectors

        self.buffer.prune(now)
        records = self.buffer.records
        vectors = compute_vectors(records, now)
        for name, scorer in self.scorers.items():
            engine = self.engines[name]
            for src_ip, vector in vectors.items():
                score, top = scorer.score(vector)
                metrics.vectors_scored_total.labels(name).inc()
                metrics.anomaly_score.labels(name, src_ip).set(score)
                outcome = engine.update(src_ip, score, top, vector, now)
                if outcome.low:
                    metrics.low_detections_total.labels(name).inc()
                if outcome.protected_hit:
                    metrics.protected_ip_hits_total.labels(name).inc()
                if outcome.capped:
                    metrics.events_capped_total.inc()
                if outcome.event is not None:
                    event = outcome.event
                    if self.rag is not None:
                        event = self.rag.annotate(event)
                    self.sink.send(event)
                    metrics.alerts_total.labels(name, event.severity).inc()
                    metrics.last_alert_timestamp.labels(name).set(now)
                    log.info(
                        "EVENT %s src_ip=%s score=%.3f severity=%s",
                        name, src_ip, event.score, event.severity,
                    )

    def run_replay(self) -> None:
        from .sources.file import FileSource

        source = FileSource(self.config.source_files)
        records = source.records
        if not records:
            log.warning("no records to replay")
            return
        self.buffer.add_many(records)
        start, end = records[0].ts, records[-1].ts
        metrics.set_ready(True)
        t = start + self.config.tick_s
        while t <= end + self.config.tick_s:
            self.score_tick(t)
            t += self.config.tick_s
        log.info("replay finished: %d records, %.0f s", len(records), end - start)

    def run_live(self) -> None:
        source = self._build_live_source()
        now = time.time()
        self.buffer.add_many(source.backfill(now, self.buffer._history_s))
        metrics.set_ready(True)
        last_ts = self.buffer.latest_ts or now
        while True:
            tick_start = time.time()
            try:
                new = source.poll_since(last_ts)
                if new:
                    self.buffer.add_many(new)
                    last_ts = max(last_ts, new[-1].ts)
            except Exception as exc:  # noqa: BLE001 - source errors must not crash the loop
                metrics.source_errors_total.inc()
                log.warning("source error: %s", exc)
            self.score_tick(time.time())
            sleep = self.config.tick_s - (time.time() - tick_start)
            if sleep > 0:
                time.sleep(sleep)

    def _build_live_source(self):
        if self.config.source == "postgres":
            from .sources.postgres import PostgresSource

            return PostgresSource(self.config.pg_dsn, self.config.pg_poll_overlap_s)
        # A file used as a (static) live source: backfill all, no new rows.
        from .sources.file import FileSource

        fs = FileSource(self.config.source_files)

        class _Static:
            def backfill(self, now: float, history_s: int):
                return fs.records

            def poll_since(self, last_ts: float):
                return []

        return _Static()

    def run(self) -> None:
        self.load_models()
        if self.config.replay:
            self.run_replay()
        else:
            self.run_live()
