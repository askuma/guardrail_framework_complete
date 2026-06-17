# guardrailprobe

**Test your AI guardrail layer, not your model. Provider-agnostic. OWASP LLM Top 10.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![PyPI version](https://img.shields.io/badge/PyPI-v0.1.0-orange.svg)](https://pypi.org/project/guardrailprobe/)
[![Probes](https://img.shields.io/badge/Probes-50%2B-green.svg)](guardrail_framework/probes.py)

---

## What it does

- **Fires 58 adversarial probes** (OWASP LLM01–LLM10) directly at your guardrail middleware — not the model — and measures what slips through
- **Compares multiple backends side-by-side** in a single run: NeMo Guardrails, GuardrailsAI, Presidio, Lakera Guard, GA Guard
- **Exports cryptographically signed PDF reports** (PKCS#12 + RFC 3161 timestamp) that you can submit to auditors or attach to EU AI Act compliance documentation

---

## Why it's different

| Tool               | Tests Model | Tests Guardrail Layer | Multi-Backend | Compliance Export |
| ------------------ | :---------: | :-------------------: | :-----------: | :---------------: |
| **guardrailprobe** |      ✗      |           ✓           |       ✓       |         ✓         |
| Garak              |      ✓      |           ✗           |       ✗       |         ✗         |
| PyRIT              |      ✓      |           ✗           |       ✗       |         ✗         |

Garak and PyRIT are excellent tools for evaluating a model's own defences. guardrailprobe solves a different problem: verifying that the guardrail **wrapper** your team ships around the model does what it says. You can swap the underlying model without re-running red-team; the guardrail layer is what ships to production.

---

## Quick install

```bash
pip install guardrailprobe
```

Or from source:

```bash
git clone https://github.com/ashuthemaddy/guardrailprobe.git
cd guardrailprobe
pip install -e ".[dev]"
alembic upgrade head
```

Copy and configure your environment:

```bash
cp .env.example .env
# set GUARDRAIL_API_KEYS and GUARDRAIL_AUTH_ENABLED
```

---

## Quickstart

```python
from guardrail_framework.red_team_runner import RedTeamRunner

runner = RedTeamRunner()

# Compare every configured backend against the full OWASP LLM Top 10
report = runner.compare_backends(
    backends=["nemo", "guardrails_ai", "presidio"],
    categories=["LLM01", "LLM06", "LLM08"],
    sensitivity="high",
)

print(f"Best overall:  {report.best_overall}")
print(f"Worst overall: {report.worst_overall}")

# ┌─────────────────┬───────┬───────┬───────┬──────────┐
# │ backend         │ LLM01 │ LLM06 │ LLM08 │ overall  │
# ├─────────────────┼───────┼───────┼───────┼──────────┤
# │ nemo            │ 1.000 │ 0.857 │ 0.833 │ 0.8966   │
# │ guardrails_ai   │ 0.875 │ 1.000 │ 0.667 │ 0.8472   │
# │ presidio        │ 0.750 │ 1.000 │ 0.500 │ 0.7500   │
# └─────────────────┴───────┴───────┴───────┴──────────┘
```

Start the API server and use the dashboard:

```bash
guardrailprobe serve
# → http://localhost:8000  (REST API + Swagger UI at /docs)
# → http://localhost:8000/app  (React dashboard — Red Team tab)
```

Run a single-backend scan from the command line:

```bash
guardrailprobe scan --backend guardrails_ai --categories LLM01,LLM04,LLM06
```

---

## Supported backends

| Backend            | PyPI package        | Notes                                              |
| ------------------ | ------------------- | -------------------------------------------------- |
| NeMo Guardrails    | `nemoguardrails`    | Colang-based rail config auto-compiled from policy |
| GuardrailsAI       | `guardrails-ai`     | YAML rail config auto-compiled from policy         |
| Microsoft Presidio | `presidio-analyzer` | PII detection; falls back to regex if SDK absent   |
| Lakera Guard       | _(REST API)_        | Requires `LAKERA_GUARD_API_KEY`                    |
| GA Guard           | _(REST API)_        | Requires `GA_GUARD_API_URL` + `GA_GUARD_API_KEY`   |

All backends degrade gracefully to regex/keyword heuristics when the SDK is not installed, so you can start testing immediately without installing any optional dependency.

---

## Documentation

- [METHODOLOGY.md](METHODOLOGY.md) — Probe construction standard, OWASP mapping, pass/fail logic, report integrity, regulatory mapping (EU AI Act, GDPR, NIST AI RMF)
- [API_REFERENCE.md](API_REFERENCE.md) — All 40+ REST endpoints
- [SETUP_GUIDE.md](SETUP_GUIDE.md) — Production deployment, PostgreSQL, Redis, Docker
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to add probes, backends, and file issues
- [benchmarks/](benchmarks/) — Community-contributed pass-rate baselines per backend

---

## Project layout

```
guardrail_framework/
  probes.py           — 58 built-in AttackProbe objects (OWASP LLM01–LLM10)
  red_team_runner.py  — RedTeamRunner, ProbeResult, RedTeamReport, ComparisonReport
  report_signer.py    — PDF generation + PKCS#12 signing + RFC 3161 timestamp
  core.py             — GuardrailFramework, all backend adapters, policy engine
  server.py           — FastAPI app, 40+ REST endpoints
  compiler.py         — Policy → Colang / YAML / Presidio config compiler
```

---

## Star this repo

If guardrailprobe saves your team an audit finding, drop a ⭐ — it helps others discover the project.

[github.com/askuma/guardrailprobe](https://github.com/askuma/guardrailprobe)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
