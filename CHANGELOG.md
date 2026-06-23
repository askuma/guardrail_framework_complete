# Changelog

All notable changes are documented here. Dates use ISO 8601 (YYYY-MM-DD).

---

## [1.2.0] — 2026-06-20

### Added

**New Backends** (`core.py`)
- `LlamaFirewallBackend` — Meta PromptGuard 2 via the `llamafirewall` SDK; fully local inference, no API key required
- `LLMGuardBackend` — `llm_guard` PromptInjection + Toxicity scanners; fully local, no API key required
- Both backends participate in the Red Team comparison table and are included in the June 2026 benchmark (85.9 % pass rate each)

**Compiler** (`compiler.py`)
- Registered all 11 backends in the `PolicyCompiler` dispatch table
- Added `_compile_generic` fallback: unknown / `CUSTOM` backends now return a portable JSON policy envelope instead of raising `ValueError`

**Public API** (`__init__.py`)
- Rewritten to export all 11 backend symbols, full OPA gap surface, testing/bundle/decision_log helpers, and `initialize()` factory function

**Dashboard**
- Visual scan progress overlay — live probe counter and per-category status during an active Red Team run
- Persistent run history — previous comparison runs stored and surfaced in the Red Team tab
- Red Team comparison table now groups backends as **General Purpose Guardrails** vs **Specialized Tools** with distinct colour-coded headers
- Footnote block added to comparison table explaining `—` cells, ★ category winners, and ⚠ low-coverage exclusion

**GitHub Pages** (`.github/workflows/pages.yml`)
- Removed `paths: docs/**` trigger filter — Pages deploy now fires on every push to `main`
- `enablement: true` on `actions/configure-pages@v5` — auto-enables GitHub Pages with GitHub Actions source
- Redesigned `docs/index.html` — light theme matching dashboard, General Purpose / Specialized grouping, live benchmark data, footnotes, archive table

**Benchmark Report** (`docs/benchmarks/benchmark_2026_06.*`)
- June 2026 benchmark: 78 probes × 11 backends; best overall OpenAI Moderation (100 %)

### Changed

- `examples.py` — updated multi-backend example to include `llama_firewall` and `llm_guard`
- `requirements.txt` — removed stale/conflicting pins; added `llamafirewall`, `llm_guard` as optional extras
- `docker-compose.yml` — pinned OTel collector image to avoid digest-change breakage

### Fixed

- `entrypoint.sh` — removed deprecated `ToxicLanguage` scanner reference that caused startup warnings
- CI (`tests/test_compiler.py`) — renamed `test_unsupported_backend` to `test_custom_backend_generic_compile` and updated assertion to match `_compile_generic` return shape

### Security

- `core.py` — introduced `_BLOCKED_RULE_KEYS = frozenset({"api_key", "api_url", "colang_policy", "nemo_yaml"})` to prevent Colang DSL injection via policy `rules` dict

---

## [1.1.0] — 2026-06-08

### Added

**Authentication**
- `APIKeyMiddleware` (`auth.py`) — header-based (`X-API-Key`) API key authentication for all endpoints
- `GUARDRAIL_API_KEYS` env var — comma-separated persistent keys; auto-generates an ephemeral key when unset and prints it to stderr
- `GUARDRAIL_AUTH_ENABLED` env var — set `false` to disable auth in development
- `/push/events` SSE route validates key via mandatory `?api_key=` query parameter (browser EventSource API cannot send custom headers)

**Persistence Layer** (`persistence.py`)
- `PersistenceLayer` class backed by SQLAlchemy — supports SQLite (dev) and PostgreSQL (production)
- `PolicyRecord` table — stores all policies; survives restarts; supports multi-replica deployments
- `BlocklistRecord` table — persistent blocklist with `entry_type` (`user`/`ip`/`keyword`), unique constraint on `(entry_type, value)`
- `load_policy(policy_id)` — single-policy lookup with Optional return, used by `_get_policy()` in core
- `save_blocklist_entry()` / `delete_blocklist_entry()` / `load_blocklist()` — full CRUD for blocklist

**Rate Limiting** (`rate_limiter.py`)
- Redis-backed distributed rate limiter via `GUARDRAIL_REDIS_URL` env var
- `_RedisWindow` — fixed-window counter using `INCR` + `EXPIRE`; key format `guardrail:rl:{policy_id}:{user_id}:{minute}`
- Fails open on Redis unavailability — outages never block legitimate traffic
- Falls back to per-process `TokenBucket` when Redis is not configured

**Database Blocklist** (`opa_gaps.py`)
- `DatabaseBlocklistProvider` — replaces `StaticBlocklistProvider` for production; TTL-cached (30 s), thread-safe
- Public mutating methods: `add_user`, `remove_user`, `add_ip`, `remove_ip`, `add_keyword`, `remove_keyword`
- Each mutation invalidates the cache immediately for consistency

**Core enhancements** (`core.py`)
- `_get_policy(policy_id)` — checks in-memory cache first, then falls back to `PersistenceLayer.load_policy()`, deserialises, and caches; enables policy discovery across replicas without restart
- SDK startup warning — logs `WARNING` at startup if no real guardrail SDK (NeMo, GuardrailsAI, Presidio, Lakera, GA Guard) is detected
- `check_input`, `check_output`, `validate_tool_call` all use `_get_policy()` so they work after a DB-only policy creation

**Database Migration**
- Alembic migration `a3f2c8b1d4e7_add_blocklist_table` — creates `blocklist` table with `ix_blocklist_entry_type` index; chained from initial schema `cac15525a8d8`

**Documentation**
- [SETUP_GUIDE.md](SETUP_GUIDE.md) — new sections: Multi-Instance / Horizontal Scaling, TLS / HTTPS (nginx + Caddy), Persistent Blocklist, GA Guard Backend
- [README.md](README.md) — root-level project README (new)
- [API_REFERENCE.md](API_REFERENCE.md) — complete REST API reference (new)
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide (new)
- [SECURITY.md](SECURITY.md) — vulnerability disclosure policy (new)

### Changed

- `requirements.txt` — Redis comment updated to document `GUARDRAIL_REDIS_URL` activation pattern

### Security

- Fixed: all route handlers now use `_get_policy()` to prevent a `KeyError` 500 on policy IDs that exist only in the database (multi-replica scenario)
- Fixed: API key authentication applied to all non-public routes; public paths explicitly allowlisted

---

## [1.0.0] — 2026-05-27

### Added

**Core Framework** (`core.py`, 3 500+ lines)
- `GuardrailFramework` — central orchestrator: policy management, backend routing, A/B test assignment
- `GuardrailPolicy` dataclass — unified policy definition covering backend, risk categories, sensitivity, action, escalation, rules, and tags
- `GuardrailResult` dataclass — normalised result with `passed`, `risk_score`, `detected_risks`, `action`, `modified_text`, `latency_ms`
- Backend implementations: `NemoGuardrailsBackend`, `GuardrailsAIBackend`, `PresidioBackend`, `LakeraGuardBackend`, `GAGuardBackend`
- Built-in regex/keyword scorer as fallback when no real SDK is installed
- `ABTestConfig` — traffic splitting with optional per-user sticky assignment

**Policy Compiler** (`compiler.py`, 1 200+ lines)
- `UnifiedPolicyBuilder` — fluent builder API
- `PolicyCompiler` — compiles unified policy to Colang DSL (NeMo), YAML validators (GuardrailsAI), JSON (Presidio)
- `PolicyTemplates` — pre-built templates: `strict_security`, `privacy_focused`, `balanced`, `agent_execution`

**Observability Stack** (`observability.py`, 1 000+ lines)
- `MetricsCollector` — time-series metric collection with configurable retention
- `AlertingSystem` — rule-based real-time alerting
- `AuditLogger` — compliance audit trails with export
- `PerformanceMonitor` — SLA tracking (P95/P99 latency, per-backend health)
- `ObservabilityStack` — unified facade

**FastAPI Server** (`server.py`)
- REST API covering all framework operations
- CORS middleware with `GUARDRAIL_CORS_ORIGINS` configuration
- Prometheus scrape endpoint at `/metrics/prometheus`

**OPA Parity Gaps** (`opa_gaps.py`)
- Gap 7: Policy pre-compilation / partial evaluation (`PolicyPrecompiler`, `/policies/{id}/precompile`, `/policies/{id}/evaluate`)
- Gap 8: Prometheus metrics export (`PrometheusMetrics`, `/metrics/prometheus`)
- Gap 9: Status API (`StatusReporter`, `/status`, `/status/{policy_id}`)
- Gap 10: WASM-ready portable scorer (`WasmReadyScorer`, `/score/text`)
- Gap 11: Pluggable external data providers (`DataProviderRegistry`, `StaticBlocklistProvider`, `/data-providers/*`)

**Additional Modules**
- `testing.py` — `PolicyTestRunner` + `PolicyTestCase`; `/test/run`, `/test/builtin/{policy_id}`
- `decision_log.py` — `DecisionLogShipper` with batched HTTP shipping; `/decision-log/*`
- `bundle.py` — OPA-format bundle export/import, polling, versioning, rollback; `/bundles/*`, `/policies/{id}/versions`, `/policies/{id}/rollback`
- `actions.py` — escalation action handlers (webhook POST, SMTP email)

**Infrastructure**
- `Dockerfile` — multi-stage build
- `docker-compose.yml` — single-container quickstart
- Alembic setup (`alembic.ini`, `migrations/`) with initial schema migration `cac15525a8d8`

**Dashboard**
- React monitoring dashboard (`guardrail_framework/dashboard.jsx`, 600+ lines)
- `patch_static.py` — build-time script to embed compiled dashboard into the FastAPI server

**Tests** — 27 tests across `tests/test_compiler.py`, `tests/test_core.py`, `tests/test_observability.py`, `tests/test_server.py`

**Documentation** — `DELIVERY_SUMMARY.md`, `IMPLEMENTATION_GUIDE.md`, `QUICK_REFERENCE.md`, `SETUP_GUIDE.md`, `INDEX.md`, `MANIFEST.md`, `guardrail_framework/README.md`, `guardrail_framework/ARCHITECTURE.md`, `guardrail_framework/OPA_PARITY.md`

---

## Format

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
