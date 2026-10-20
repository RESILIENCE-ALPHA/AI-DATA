"""In-loop RAG call to Ollama, with a hard timeout and ML fallback.

The LLM only confirms or narrows the ML recommendation; it never invents a
command. Its action must be in the allowlist, or the ML action is used. On
timeout, HTTP error, or invalid JSON, the ML action is used. This keeps the
remediation loop deterministic even when the model is slow (CLAUDE.md step 5).
"""

from __future__ import annotations

import json

import httpx

from .schema import AnomalyEvent

ACTION_ALLOWLIST = {"block_ip", "restart_service", "rate_limit"}

_SYSTEM = (
    "You are a security remediation assistant. You are given a detected anomaly and the "
    "ML-recommended action. Reply ONLY with JSON: "
    '{"action": "<one of block_ip|restart_service|rate_limit>", "explanation": "<one sentence>"}. '
    "Choose the recommended action unless the evidence clearly contradicts it. "
    "Never invent commands or other fields."
)


class RagClient:
    def __init__(self, url: str, model: str, timeout_s: float = 9.0) -> None:
        self._url = url.rstrip("/") + "/api/generate"
        self._model = model
        self._timeout = timeout_s

    def annotate(self, event: AnomalyEvent) -> AnomalyEvent:
        """Return the event enriched with rag_action / rag_explanation.

        Falls back to the ML recommended action on any problem.
        """
        ml_action = event.recommended_actions[0] if event.recommended_actions else "block_ip"
        prompt = (
            f"{_SYSTEM}\n\nAnomaly: detector={event.detector} severity={event.severity} "
            f"score={event.score} src_ip={event.src_ip} "
            f"evidence={event.evidence.model_dump()}\n"
            f"ML recommended action: {ml_action}\nJSON:"
        )
        try:
            resp = httpx.post(
                self._url,
                json={
                    "model": self._model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0},
                },
                timeout=self._timeout,
            )
            resp.raise_for_status()
            text = resp.json().get("response", "")
            parsed = json.loads(text)
            action = str(parsed.get("action", "")).strip()
            explanation = str(parsed.get("explanation", "")).strip()
            if action in ACTION_ALLOWLIST:
                event.rag_action = action
                event.rag_explanation = explanation or None
                return event
        except (httpx.HTTPError, json.JSONDecodeError, ValueError, KeyError):
            pass
        event.rag_action = ml_action
        event.rag_explanation = "ML fallback (RAG unavailable or invalid response)"
        return event
