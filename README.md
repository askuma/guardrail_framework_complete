# guardrailprobe

**Test your AI guardrail layer, not your model. Provider-agnostic. OWASP LLM Top 10.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![PyPI version](https://img.shields.io/badge/PyPI-v0.1.0-orange.svg)](https://pypi.org/project/guardrailprobe/)
[![Probes](https://img.shields.io/badge/Probes-70%2B-green.svg)](guardrail_framework/probes.py)

---

## What it does

- **Fires 70+ adversarial probes** (OWASP LLM01–LLM10 + content moderation CM-001–CM-020) directly at your guardrail middleware — not the model — and measures what slips through
- **Compares multiple backends side-by-side** in a single run: NeMo Guardrails, GuardrailsAI, Presidio, Lakera Guard, GA Guard, OpenAI Moderation, Azure Content Safety, Azure Prompt Shields, AWS Bedrock
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
git clone https://github.com/askuma/guardrailprobe.git
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

## Deployment

**Docker Compose (recommended):**

```bash
cp .env.example .env          # set GUARDRAIL_API_KEYS at minimum
docker compose up -d
```

**Local development:**

```bash
pip install -e ".[dev]"
alembic upgrade head          # copy docs/alembic.ini to project root first
uvicorn guardrail_framework.server:app --reload
```

**Horizontal scaling** requires two additional env vars:

```bash
GUARDRAIL_DB_URL=postgresql://user:pass@db-host:5432/guardrail   # shared policy store
GUARDRAIL_REDIS_URL=redis://redis-host:6379/0                     # cross-replica rate limiter
```

Always put a TLS-terminating reverse proxy (nginx, Caddy) in front of uvicorn.
Full deployment guide including Docker single-container, PostgreSQL, Redis, TLS config,
and production checklist: [docs/implementation.md](docs/implementation.md)

For database migration config: [docs/alembic.ini](docs/alembic.ini)

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

| Backend | Type | Credential Required |
|---------|------|-------------------|
| NeMo Guardrails | Local SDK | Optional LLM API key |
| GuardrailsAI | Local SDK | Optional LLM API key |
| Microsoft Presidio | Local SDK | None — fully local |
| Lakera Guard | Cloud REST API | `LAKERA_GUARD_API_KEY` |
| GA Guard | Cloud REST API | `GA_GUARD_API_URL` + `GA_GUARD_API_KEY` |
| OpenAI Moderation | Cloud REST API | `OPENAI_API_KEY` |
| Azure Content Safety | Cloud REST API | `AZURE_CONTENT_SAFETY_ENDPOINT` + `AZURE_CONTENT_SAFETY_KEY` |
| Azure Prompt Shields | Cloud REST API | `AZURE_CONTENT_SAFETY_ENDPOINT` + `AZURE_CONTENT_SAFETY_KEY` |
| AWS Bedrock Guardrails | Cloud Managed | AWS credentials + `AWS_BEDROCK_GUARDRAIL_ID` |

All backends degrade gracefully when credentials are missing — they appear as SKIPPED in
benchmark reports rather than showing misleading 0% scores.

---

## Benchmark Reports

Monthly independent benchmark reports comparing all supported backends against OWASP LLM
Top 10 and content moderation probe suites.

Latest report: [benchmarks/](benchmarks/)
Live dashboard: https://askuma.github.io/guardrailprobe

Reports include:
- Per-backend pass rates across all OWASP categories
- Content moderation scores (Hate / Violence / Sexual / Self-harm)
- Accuracy vs latency tradeoff analysis
- Month-over-month regression tracking
- Cryptographically signed PDF for audit submission

## Independence Statement

guardrailprobe has no commercial relationship with any tested backend provider. NVIDIA,
Microsoft, OpenAI, Lakera, General Analysis, and Amazon do not fund, endorse, or influence
this project.

Probe library, methodology, and scoring logic are fully open source and independently
auditable. See [METHODOLOGY.md](METHODOLOGY.md) for details.

---

## Documentation

- [METHODOLOGY.md](METHODOLOGY.md) — Probe construction standard, OWASP mapping, pass/fail logic, report integrity, regulatory mapping (EU AI Act, GDPR, NIST AI RMF)
- [API_REFERENCE.md](API_REFERENCE.md) — All 54 REST endpoints
- [docs/implementation.md](docs/implementation.md) — Production deployment, PostgreSQL, Redis, Docker, TLS
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to add probes, backends, and file issues
- [benchmarks/](benchmarks/) — Monthly benchmark reports

---

## Project layout

```
guardrail_framework/
  probes.py           — 70+ built-in AttackProbe objects
                        OWASP LLM01–LLM10 adversarial probes +
                        CM-001–CM-020 content moderation probes
                        (Hate, Violence, Sexual, Self-harm)
  red_team_runner.py  — RedTeamRunner, ComparisonReport
  report_signer.py    — PDF + PKCS#12 + RFC 3161
  core.py             — GuardrailFramework, 9 backends
  server.py           — FastAPI, 54 REST endpoints
  compiler.py         — Policy compiler

benchmark_report.py   — Monthly benchmark generator
benchmarks/           — Published benchmark reports
docs/                 — GitHub Pages benchmark site
```

---

## Star this repo

If guardrailprobe saves your team an audit finding, drop a ⭐ — it helps others discover the project.

[github.com/askuma/guardrailprobe](https://github.com/askuma/guardrailprobe)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
