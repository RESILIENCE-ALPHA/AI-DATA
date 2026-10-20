"""RAG step inside the remediation loop: LangChain + Mistral 7B on Ollama.

For each anomaly event:
1. retrieve the most relevant runbook passages (vector search over `runbooks/`),
2. ask the local LLM (Mistral 7B by default, under the 8B-parameter limit) to
   confirm one action and explain it, as strict JSON
   `{"action": "...", "explanation": "..."}`, temperature 0,
3. accept the answer only if `action` is in the allowlist.

Safety rules (CLAUDE.md, detector flow step 5): the LLM never produces commands;
on timeout, error, invalid JSON or a forbidden action, the ML recommended action
is sent anyway. So a slow or wrong model can never stall the remediation.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from pathlib import Path

from .schema import AnomalyEvent

log = logging.getLogger("detector.rag")

ACTION_ALLOWLIST = ("block_ip", "restart_service")

SYSTEM_PROMPT = (
    "You are the remediation assistant of a payment platform under attack. "
    "An ML detector flagged an anomaly. Using only the runbook context and the event, "
    "choose ONE action from this list: {allowed}. "
    "Keep the ML recommended action unless the evidence clearly contradicts it. "
    "Answer with JSON only, no other text: "
    '{{"action": "<one of the list>", "explanation": "<one short sentence for the dashboard>"}}. '
    "Never write commands, code, or any other field."
)

USER_PROMPT = (
    "Runbook context:\n{context}\n\n"
    "Anomaly event:\n{event}\n\n"
    "ML recommended action: {ml_action}\nJSON:"
)


def load_runbook_chunks(docs_dir: str | Path, max_chars: int = 1200) -> list[str]:
    """Split every Markdown file of the runbooks folder into paragraphs-sized chunks."""
    chunks: list[str] = []
    base = Path(docs_dir)
    if not base.exists():
        return chunks
    for path in sorted(base.rglob("*.md")):
        text = path.read_text(errors="ignore")
        buf = ""
        for para in text.split("\n\n"):
            if len(buf) + len(para) > max_chars and buf:
                chunks.append(f"[{path.name}] {buf.strip()}")
                buf = ""
            buf += para + "\n\n"
        if buf.strip():
            chunks.append(f"[{path.name}] {buf.strip()}")
    return chunks


class RagAdvisor:
    """Annotate events with an LLM decision; fall back to the ML action on any problem."""

    def __init__(self, llm, retriever=None, timeout_s: float = 9.0, k: int = 3) -> None:
        from langchain_core.output_parsers import JsonOutputParser
        from langchain_core.prompts import ChatPromptTemplate

        prompt = ChatPromptTemplate.from_messages(
            [("system", SYSTEM_PROMPT), ("human", USER_PROMPT)]
        )
        self._chain = prompt | llm | JsonOutputParser()
        self._retriever = retriever
        self._timeout = timeout_s
        self._k = k
        self._pool = ThreadPoolExecutor(max_workers=1)

    @classmethod
    def from_config(
        cls, ollama_url: str, model: str, timeout_s: float,
        docs_dir: str = "runbooks", embed_model: str = "nomic-embed-text",
    ) -> RagAdvisor:
        from langchain_ollama import ChatOllama

        llm = ChatOllama(
            base_url=ollama_url, model=model, temperature=0, format="json",
            client_kwargs={"timeout": timeout_s},
        )
        return cls(llm, retriever=cls._build_retriever(ollama_url, docs_dir, embed_model),
                   timeout_s=timeout_s)

    @staticmethod
    def _build_retriever(ollama_url: str, docs_dir: str, embed_model: str):
        """Vector store over the runbooks; None if there are no runbooks or no embeddings."""
        chunks = load_runbook_chunks(docs_dir)
        if not chunks:
            log.warning("no runbooks in %s: RAG runs without retrieved context", docs_dir)
            return None
        try:
            from langchain_core.vectorstores import InMemoryVectorStore
            from langchain_ollama import OllamaEmbeddings

            store = InMemoryVectorStore.from_texts(
                chunks, embedding=OllamaEmbeddings(base_url=ollama_url, model=embed_model)
            )
            log.info("indexed %d runbook chunks", len(chunks))
            return store
        except Exception as exc:  # noqa: BLE001 - retrieval is optional
            log.warning("runbook index unavailable (%s): RAG runs without context", exc)
            return None

    def _context(self, query: str) -> str:
        if self._retriever is None:
            return "(no runbook available)"
        docs = self._retriever.similarity_search(query, k=self._k)
        return "\n---\n".join(d.page_content for d in docs) or "(no relevant passage)"

    def _ask(self, event: AnomalyEvent, ml_action: str) -> dict:
        event_json = event.model_dump_json(exclude={"rag_action", "rag_explanation"})
        context = self._context(f"{event.detector} {event.target_service} {ml_action}")
        return self._chain.invoke({
            "allowed": ", ".join(ACTION_ALLOWLIST),
            "context": context,
            "event": event_json,
            "ml_action": ml_action,
        })

    def annotate(self, event: AnomalyEvent) -> AnomalyEvent:
        ml_action = event.recommended_actions[0] if event.recommended_actions else "block_ip"
        started = time.monotonic()
        reason = "invalid answer"
        try:
            answer = self._pool.submit(self._ask, event, ml_action).result(timeout=self._timeout)
            action = str(answer.get("action", "")).strip() if isinstance(answer, dict) else ""
            if action in ACTION_ALLOWLIST:
                event.rag_action = action
                event.rag_explanation = str(answer.get("explanation", "")).strip() or None
                log.info("rag ok in %.1f s: %s", time.monotonic() - started, action)
                return event
            reason = f"action not allowed: {action!r}"
        except FutureTimeout:
            reason = f"timeout after {self._timeout:.0f} s"
        except ValueError as exc:  # includes JSON and LangChain output-parser errors
            reason = f"invalid JSON ({exc})"
        except Exception as exc:  # noqa: BLE001 - any LLM failure must fall back to ML
            reason = f"error ({type(exc).__name__})"
        log.warning("rag fallback to ML action: %s", reason)
        event.rag_action = ml_action
        event.rag_explanation = f"ML fallback: {reason}"
        return event
