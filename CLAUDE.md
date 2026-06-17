# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Setup
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Database migrations (required before first run)
alembic upgrade head

# Run the API server
uvicorn guardrail_framework.server:app --host 0.0.0.0 --port 8000 --reload

# Run all tests
pytest tests/ -v

# Run a single test
pytest tests/test_server.py::test_health_check -v

# Docker (single container, SQLite persisted in named volume)
docker-compose up
```

The server exposes Swagger UI at `/docs` and Prometheus metrics at `/metrics/prometheus`.

## Environment

Copy `.env.example` to `.env` before running. Key variables:

| Variable | Default | Notes |
|---|---|---|
| `GUARDRAIL_API_KEYS` | *(auto-generated ephemeral)* | Comma-separated keys; set this or clients will break on restart |
| `GUARDRAIL_AUTH_ENABLED` | `true` | Set `false` in dev to skip auth |
| `GUARDRAIL_DB_URL` | `sqlite:///guardrail.db` | Use `postgresql://...` for production |
| `GUARDRAIL_REDIS_URL` | *(unset)* | Enable for cross-replica rate limiting |

All API requests require `X-API-Key: <key>` header, except `/health`, `/ready`, `/docs`, `/redoc`, `/metrics/prometheus`, and `/push/events` (the SSE endpoint instead accepts `?api_key=` query param because browsers can't set custom headers for EventSource).

## Architecture

### Module map

```
guardrail_framework/
  core.py          — GuardrailFramework, GuardrailPolicy, all backend adapters, ActionType, RiskCategory
  compiler.py      — UnifiedPolicyBuilder, PolicyCompiler (converts policy → Colang / YAML / Presidio config)
  server.py        — FastAPI app, 40+ REST endpoints, lifespan startup/shutdown
  auth.py          — APIKeyMiddleware, load_api_keys
  persistence.py   — SQLAlchemy ORM: policies, audit_log, blocklist, ab_tests tables
  observability.py — ObservabilityStack: metrics, alerting, in-memory audit collector
  rate_limiter.py  — Token-bucket rate limiter; Redis-backed when GUARDRAIL_REDIS_URL is set
  bundle.py        — OPA-parity: policy bundle distribution (tar.gz), versioning/rollback, SSE push
  opa_gaps.py      — OPA-parity: partial evaluation/precompilation, Prometheus export, status API, WASM-safe scoring
  actions.py       — Action handlers: block, redact, rewrite, escalate, log_only
  decision_log.py  — Decision log shipper (background thread)
  testing.py       — Test utilities and helpers
```

### How the layers connect

1. **Policy lifecycle**: `UnifiedPolicyBuilder` builds a `GuardrailPolicy` dataclass → `PolicyCompiler` compiles it to backend-specific config (Colang for NeMo, YAML for GuardrailsAI, Presidio config) → stored via `PersistenceLayer` (SQLAlchemy) and held in `GuardrailFramework.policies` dict.

2. **Check path**: `framework.check_input()` → backend adapter → `ObservabilityStack.record()` → `PersistenceLayer` (audit log). The backend is selected per-policy; A/B tests split traffic by `hash(user_id)` for sticky routing.

3. **Backend detection**: optional SDKs (NeMo, GuardrailsAI, Presidio) are detected at import time via `importlib.util.find_spec`. When absent, backends fall back to regex/pattern-matching heuristics — the framework is usable without any external SDK installed.

4. **Framework singleton**: `get_framework()` returns a module-level `GuardrailFramework` instance. The server wires `PersistenceLayer` into it at startup via the FastAPI `lifespan` context manager; `framework.load_from_persistence()` rehydrates policies and blocklist from the DB.

5. **SSE real-time push** (`/push/events`): implemented in `bundle.py`'s `SSEChannel`; policy changes broadcast to all connected clients.

6. **OPA parity**: `bundle.py` covers Gaps 1–6 (bundle distribution, versioning, SSE). `opa_gaps.py` covers Gaps 7–11 (precompilation, Prometheus, status API, WASM scoring, pluggable data providers). The `PolicyPrecompiler` in `opa_gaps.py` is wired as `_precompiler` at server startup and used on the hot evaluation path.

### Database

SQLite by default; PostgreSQL for production. Alembic manages migrations under `migrations/`. The `env.py` reads `GUARDRAIL_DB_URL` at migration time so credentials never appear in `alembic.ini`. SQLite requires `render_as_batch=True` for ALTER TABLE support (already configured).

### Testing

Tests use `FastAPI.testclient` (httpx under the hood). Set `GUARDRAIL_API_KEYS=test-key` and `GUARDRAIL_AUTH_ENABLED=true` before importing the server — `test_server.py` does this at module level. Run the full suite with `pytest tests/ -v`; individual test files are `test_core.py`, `test_compiler.py`, `test_observability.py`, and `test_server.py`.
