# AI-DATA — RESILIENCE-ALPHA

IA/DATA pillar of the EPSI M2 workshop **RESILIENCE-ALPHA**: an ML anomaly detector that
spots a brute force on the payment platform's login, a local RAG step that annotates each
detection with a local LLM, and a remediation executor that blocks the attacker's IP in
APISIX, with no human action. The same service also receives CYBER's Falco runtime alerts
on `/remediate`.

> Status: work in progress (v0.1). Design docs are being updated to v0.4 and will be
> added to `docs/` once they match the team decisions.

## How it works

```
login_attempts (DEV, Postgres)  ──►  service-ia  ──►  block attacker IP in APISIX (TTL 15 min)
   or synthetic JSON lines           │               (ip-restriction global rule, no human action)
                                      ├─ every 5 s: features per source IP
                                      ├─ Isolation Forest score (0..1)
                                      ├─ decision: 2 ticks, cooldown, cap, protected IPs
                                      ├─ RAG: LangChain + Mistral 7B on Ollama (timeout + ML fallback)
                                      ├─ executor: block_ip (APISIX), restart_service (bonus)
                                      ├─ /remediate on :5000  ◄── CYBER Falco / Falcosidekick
                                      └─ /metrics, /healthz, /readyz on :9108
```

- **Source**: DEV's `login_attempts` table (live, read-only user) or a JSON-lines file
  in the same shape (tests, replay).
- **Features**: per source IP over 10 s and 60 s windows, a 5 min history, and global
  features. One module (`src/detector/features.py`) is used for training and serving.
- **Model**: Isolation Forest (`auth_bruteforce`) trained on **normal traffic only**, so it
  does not need to know the attack in advance. Score mapped to 0..1.
- **Decision**: score above threshold on 2 consecutive ticks; cooldown 300 s per IP;
  global cap; protected-IP list.
- **Tracked in MLflow**: every training run logs its parameters, metrics and model files;
  the model is registered as `auth_bruteforce` and gets the `production` alias only when
  the evaluation gate passes (detected, delay ≤ 15 s, no false positive).
- **RAG in the loop**: LangChain retrieves the relevant runbook passages (`runbooks/`) and
  asks **Mistral 7B** (7.3B parameters, under the 8B limit) on the cluster's Ollama to
  confirm one action (`block_ip` or `restart_service`) and explain it, as strict JSON at
  temperature 0. On timeout (9 s), invalid JSON or a forbidden action, the ML action is
  sent anyway. The LLM never produces commands.

## Anomaly event (logged to stdout/Loki, drives the executor)

```json
{
  "event_id": "9f3c2a1e-6b7d-4c1a-9e5f-2d8b1a0c4e77",
  "ts": "2026-10-20T14:02:05Z",
  "detector": "auth_bruteforce",
  "model_version": "0.1.0",
  "severity": "high",
  "score": 0.99,
  "src_ip": "203.0.113.42",
  "target_service": "auth",
  "recommended_actions": ["block_ip", "restart_service"],
  "evidence": {
    "n_fail_60s": 312,
    "n_success_60s": 0,
    "n_distinct_users_60s": 5,
    "req_per_s_60s": 5.2,
    "top_features": ["n_fail_10s", "req_per_s_60s", "max_burst_1s_10s"]
  },
  "rag_action": "block_ip",
  "rag_explanation": "One IP produced hundreds of failed logins in a minute."
}
```

`event_id` is the idempotency key: the receiver must ignore duplicates. `severity` is
`medium` or `high`. Example IPs use the RFC 5737 documentation ranges.

## Quick start

Requires Python 3.12 and [uv](https://github.com/astral-sh/uv).

```bash
make setup      # venv + dependencies
make data       # synthetic datasets (normal, brute force, hard)
make features   # labelled feature tables
make train      # train the Isolation Forest
make evaluate   # detection delay, false positives, gate -> reports/ + MLflow
make mlflow-ui  # browse runs and the model registry on http://127.0.0.1:5000
make test       # unit + end-to-end tests
make replay     # replay the brute-force capture through the service
```

Runtime configuration is environment variables; see `.env.example`.

## Layout

```
src/detector/     service: schema, features, scorer, decision, sources, sinks, metrics, RAG,
                  executor (APISIX block), receiver (Falco /remediate on :5000)
deploy/           Dockerfile (repo root) + ia-service.yaml (service-ia in namespace ia)
src/generator/    synthetic login_attempts data with labels
src/training/     build_features, train (MLflow), evaluate (MLflow + promotion)
runbooks/         remediation runbooks indexed by the RAG step
tests/            unit tests and an end-to-end pipeline test
params.yaml       generator, feature and model parameters
```

`data/`, `models/`, `events/` and the MLflow store (`mlflow.db`, `mlruns/`) are generated
locally and never committed.
