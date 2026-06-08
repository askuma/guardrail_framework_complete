# Contributing

Thank you for your interest in contributing to Guardrail Framework.

## Development Setup

```bash
git clone https://github.com/yourorg/guardrail-framework.git
cd guardrail-framework

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install all dependencies
pip install -r requirements.txt
pip install -e .

# Copy environment config
cp .env.example .env
# Edit .env — set GUARDRAIL_API_KEYS at minimum

# Apply database migrations
alembic upgrade head

# Verify everything works
pytest tests/ -v
```

## Running the Server Locally

```bash
uvicorn guardrail_framework.server:app --reload --port 8000
# Swagger UI: http://localhost:8000/docs
```

## Project Structure

```
guardrail_framework/
├── core.py           # GuardrailFramework, policies, backends, A/B testing
├── compiler.py       # UnifiedPolicyBuilder, PolicyCompiler, PolicyTemplates
├── observability.py  # MetricsCollector, AlertingSystem, AuditLogger
├── server.py         # FastAPI application — all REST endpoints
├── auth.py           # APIKeyMiddleware, load_api_keys
├── persistence.py    # PersistenceLayer (SQLAlchemy), PolicyRecord, BlocklistRecord
├── rate_limiter.py   # PolicyRateLimiter, Redis backend, TokenBucket fallback
├── opa_gaps.py       # PrometheusMetrics, WasmReadyScorer, DataProviderRegistry, …
├── testing.py        # PolicyTestRunner, PolicyTestCase
├── decision_log.py   # DecisionLogShipper
├── bundle.py         # BundleBuilder, BundlePoller, PolicyVersionStore
└── actions.py        # Escalation handlers (webhook, SMTP)

tests/
├── test_compiler.py
├── test_core.py
├── test_observability.py
└── test_server.py

migrations/
└── versions/         # Alembic migration scripts
```

## Tests

Run the full suite:

```bash
pytest tests/ -v
```

Run a specific file:

```bash
pytest tests/test_core.py -v
```

Run with coverage:

```bash
pip install pytest-cov
pytest tests/ --cov=guardrail_framework --cov-report=term-missing
```

**Requirements for new code:**
- All new modules must have corresponding test coverage
- Use `pytest` and `pytest-asyncio` for async routes
- Use `httpx` test client for FastAPI endpoint tests — do not mock the framework instance at the HTTP boundary

## Code Style

- Python 3.9+ syntax
- Follow the existing patterns in each file — no new abstractions without discussion
- Keep functions focused; prefer flat code over nested helpers
- Write no docstrings on private helpers; public API methods should have a one-line docstring maximum
- No comments on obvious code; add one only when the WHY is non-obvious (hidden constraint, workaround, surprising invariant)

## Adding a New Backend

1. Add a new value to the `GuardrailBackend` enum in `core.py`
2. Implement `GuardrailBackendInterface` — `check_input`, `check_output`, `validate_tool_call`, `apply_policy`
3. Wire it up in `GuardrailFramework._initialize_backends()`
4. Add compiler support in `compiler.py` (`PolicyCompiler.compile` switch)
5. Add the SDK to `requirements.txt` as an optional commented dependency
6. Update `_initialize_backends` to detect if the SDK is available
7. Add tests in `tests/test_core.py`

## Adding a New REST Endpoint

1. Add the route handler in `server.py`
2. Use an existing tag (`"Policies"`, `"Observability"`, etc.) or add a new one for a new feature group
3. Define a Pydantic request model if the endpoint accepts a body
4. Add a test in `tests/test_server.py` using the `httpx` test client
5. Document the endpoint in `API_REFERENCE.md`

## Database Migrations

When changing the schema (adding tables or columns):

```bash
# Auto-generate a migration from model changes
alembic revision --autogenerate -m "describe_your_change"

# Review the generated file in migrations/versions/ before committing
alembic upgrade head   # apply locally to verify

# Include the migration file in your PR
```

Never edit an existing migration that has already been applied to any environment. Create a new migration instead.

## Pull Request Guidelines

- Keep PRs focused — one logical change per PR
- Include tests for all new behaviour
- Update `CHANGELOG.md` under an `[Unreleased]` section
- Update `API_REFERENCE.md` if you add or change REST endpoints
- Ensure `pytest tests/ -v` passes before opening the PR
- Target the `main` branch

## Security Issues

Do not open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.
