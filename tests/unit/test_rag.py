"""RAG step: valid answer, forbidden action, invalid JSON and timeout all behave safely.

Uses LangChain fake/lambda models, so no Ollama is needed in tests.
"""

import time

import pytest

pytest.importorskip("langchain_core")

from langchain_core.language_models.fake_chat_models import FakeListChatModel  # noqa: E402
from langchain_core.runnables import RunnableLambda  # noqa: E402

from detector.rag import RagAdvisor, load_runbook_chunks  # noqa: E402
from detector.schema import AnomalyEvent, Evidence  # noqa: E402


def _event() -> AnomalyEvent:
    return AnomalyEvent(
        event_id="e1", ts="2026-10-20T14:00:00Z", detector="auth_bruteforce",
        model_version="0.1.0", severity="medium", score=0.93, src_ip="203.0.113.9",
        target_service="auth", recommended_actions=["block_ip", "restart_service"],
        evidence=Evidence(n_fail_60s=61, top_features=["req_per_s_10s"]),
    )


def test_valid_answer_is_used():
    llm = FakeListChatModel(responses=['{"action": "block_ip", "explanation": "61 failures."}'])
    ev = RagAdvisor(llm, timeout_s=5).annotate(_event())
    assert ev.rag_action == "block_ip"
    assert ev.rag_explanation == "61 failures."


def test_forbidden_action_falls_back_to_ml():
    llm = FakeListChatModel(responses=['{"action": "rm -rf /", "explanation": "x"}'])
    ev = RagAdvisor(llm, timeout_s=5).annotate(_event())
    assert ev.rag_action == "block_ip"
    assert ev.rag_explanation.startswith("ML fallback")


def test_invalid_json_falls_back_to_ml():
    llm = FakeListChatModel(responses=["I think you should block it"])
    ev = RagAdvisor(llm, timeout_s=5).annotate(_event())
    assert ev.rag_action == "block_ip"
    assert "ML fallback" in ev.rag_explanation


def test_timeout_falls_back_to_ml():
    def slow(_):
        time.sleep(2)
        return '{"action": "restart_service", "explanation": "late"}'

    ev = RagAdvisor(RunnableLambda(slow), timeout_s=0.3).annotate(_event())
    assert ev.rag_action == "block_ip"
    assert "timeout" in ev.rag_explanation


def test_runbook_chunks_loaded():
    chunks = load_runbook_chunks("runbooks")
    assert chunks and all(c.startswith("[") for c in chunks)
