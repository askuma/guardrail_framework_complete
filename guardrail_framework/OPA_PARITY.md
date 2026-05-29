# OPA Feature Parity — Implementation Guide

This release closes the 11 gaps between the Guardrail Framework and Open Policy Agent.
Each gap is a self-contained module wired into `core.py` and exposed via `server.py`.

## New modules

| Module | Gaps | What it adds |
|--------|------|--------------|
| `testing.py`       | 1, 2 | `PolicyTestRunner`, `PolicyTestCase`, `fail_closed_result` |
| `decision_log.py`  | 3    | `DecisionLogShipper`, `DecisionEvent` |
| `bundle.py`        | 4, 5, 6 | `BundleBuilder/Loader/Poller`, `PolicyVersionStore`, `PolicyPushChannel` |
| `opa_gaps.py`      | 7–11 | `PolicyPrecompiler`, `PrometheusMetrics`, `StatusReporter`, `WasmReadyScorer`, data providers |

---

## Gap 1 — Policy unit testing

```python
from guardrail_framework import PolicyTestRunner, PolicyTestCase

runner = PolicyTestRunner(framework)
runner.expect_allowed("safe query", "What is the weather?", policy_id, risk_max=0.5)
runner.expect_blocked("sql injection", "DROP TABLE users;", policy_id, risk_min=0.3)

report = runner.run_all()
print(report.summary())
assert report.failed == 0
```

REST: `POST /test/run` (custom cases) · `GET /test/builtin/{policy_id}` (smoke suite)

## Gap 2 — Default-deny posture

All three check methods (`check_input`, `check_output`, `validate_tool_call`) now
fail closed: a missing policy, unconfigured backend, or backend exception returns a
**blocking** `GuardrailResult` with `risk_score=1.0` instead of raising.
`GuardrailPolicy.action_on_violation` already defaults to `BLOCK`.

## Gap 3 — Remote decision log shipping

```python
from guardrail_framework import DecisionLogShipper, DecisionEvent

shipper = DecisionLogShipper(sink_url="https://logs.example.com/decisions",
                             max_chunk_size=100, flush_interval_secs=10)
shipper.start()
shipper.enqueue_from_result(result, policy_id, policy_name, "input_check")
```

Async queue, chunked uploads, exponential backoff, `upload_size_limit_bytes` splitting.
REST: `POST /decision-log/configure` · `GET /decision-log/stats` · `POST /decision-log/stop`

## Gap 4 — Bundle distribution

OPA-compatible tar.gz bundles (`.manifest` + `policies/*.json`).

```python
from guardrail_framework import BundleBuilder, BundleLoader, BundlePoller

raw  = BundleBuilder.build(framework.policies, bundle_name="prod")
meta = BundleLoader.load(raw, framework, version_store)

poller = BundlePoller("https://config.example.com/bundle.tar.gz",
                      framework, interval_secs=30, version_store=version_store)
poller.start()   # polls, verifies SHA-256, atomically swaps on change
```

REST: `GET /bundles/export` · `POST /bundles/import` · `POST /bundles/poller/start|stop`

## Gap 5 — Policy versioning & rollback

```python
from guardrail_framework import PolicyVersionStore

store = PolicyVersionStore(max_versions_per_policy=20)
framework._version_store = store     # auto-snapshots on create/update

history = store.history(policy_id)            # newest first
store.rollback(framework, policy_id, snapshot_id)
```

REST: `GET /policies/{id}/versions` · `POST /policies/{id}/rollback`

## Gap 6 — Real-time policy push (SSE)

Every create/update/delete/rollback broadcasts an event to all connected clients.

```javascript
const es = new EventSource("/push/events");
es.onmessage = e => console.log(JSON.parse(e.data));
// { type: "policy_updated", policy_id: "...", changes: ["sensitivity"] }
```

REST: `GET /push/events` (SSE stream) · `GET /push/stats`

## Gap 7 — Partial evaluation

Pre-compiles regex patterns + weight tables for a `(policy_id, context)` pair so the
hot path skips recompilation. LRU-style eviction, cache invalidation on policy update.

```python
from guardrail_framework import PolicyPrecompiler

pc = PolicyPrecompiler(framework)
rq = pc.compile(policy_id, context={"env": "prod", "tenant": "acme"})
score, risks = pc.evaluate(rq, text)    # cheap repeated evaluation
```

REST: `POST /policies/{id}/precompile` · `POST /policies/{id}/evaluate` · `GET /precompiler/stats`

## Gap 8 — Prometheus / OpenTelemetry metrics

Uses `prometheus_client` when installed; falls back to in-memory counters otherwise.
Exposes `guardrail_decisions_total`, `guardrail_decision_duration_seconds`,
`guardrail_risk_score`, `guardrail_active_policies_total`, `guardrail_bundle_loads_total`.

REST: `GET /metrics/prometheus` (scrape endpoint)

## Gap 9 — Status API

Per-policy health: last-check time, total/blocked counts, error rate, avg + p95 latency.

REST: `GET /status` (all policies) · `GET /status/{policy_id}`

## Gap 10 — WASM-ready portable scorer

`WasmReadyScorer` is the single source of truth for risk scoring (both NeMo and
GuardrailsAI backends now delegate to it). Pure stdlib (`re`, `json`) so it compiles
to WASM via Pyodide / Emscripten for edge deployment.

```python
from guardrail_framework import WasmReadyScorer
scorer = WasmReadyScorer()
score, risks = scorer.score(text, sensitivity="high")
json_out = scorer.score_text_wasm(text, "high")    # JSON boundary for JS/WASM
```

REST: `POST /score/text`

## Gap 11 — Pluggable external data providers

Enrich every check with live data (blocklists, threat feeds, user attributes).
Providers run before each check; they only *add* keys, never overwrite caller context.

```python
from guardrail_framework import DataProviderRegistry, StaticBlocklistProvider, HttpDataProvider

data_registry.register(StaticBlocklistProvider(blocked_users=["evil-user"]))
data_registry.register(HttpDataProvider("https://threatfeed.example.com/data", ttl_secs=60))
# GuardrailFramework.check_input now auto-enriches context
```

REST: `POST /data-providers/blocklist` · `GET /data-providers/stats` · `POST /data-providers/enrich`

---

## Server route count

The FastAPI app grew from 24 to **49 routes**. All new routes are tagged in the
OpenAPI docs at `/docs` under: Policy Testing, Decision Logging, Bundle Distribution,
Versioning, Real-time Push, Partial Evaluation, Observability, WASM Scorer, Data Providers.

## Backwards compatibility

- Existing `check_input/output/validate_tool_call` signatures unchanged.
- `create_policy` / `update_policy` gained optional `created_by` / `reason` kwargs (default-safe).
- Risk scoring is now stronger (injection patterns catch multi-word qualifiers); policies
  that previously passed borderline injections may now block them — this is the intended fix.
