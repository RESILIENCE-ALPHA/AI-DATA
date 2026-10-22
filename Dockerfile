# IA/DATA detector + remediation executor + Falco receiver.
# One container runs: the ML poller on login_attempts, the APISIX block executor,
# and the /remediate receiver CYBER's Falcosidekick posts to.
FROM python:3.12-slim AS build

WORKDIR /app
COPY pyproject.toml requirements.txt ./
COPY src ./src
# Base + postgres source + RAG (LangChain/Ollama). MLflow is training-only, excluded.
RUN pip install --no-cache-dir ".[postgres,rag]"

# Promoted model and runbooks are baked in (models/ is git-ignored; present at build).
COPY models ./models
COPY runbooks ./runbooks

ENV MODELS_DIR=/app/models \
    PYTHONUNBUFFERED=1

# Non-root. 5000 = Falco receiver (/remediate); 9108 = /metrics, /healthz, /readyz.
USER 65532:65532
EXPOSE 5000 9108

CMD ["python", "-m", "detector"]
