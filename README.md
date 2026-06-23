# guardrailprobe

**Test your AI guardrail layer, not your model. Provider-agnostic. OWASP LLM Top 10.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![PyPI version](https://img.shields.io/badge/PyPI-v0.1.0-orange.svg)](https://pypi.org/project/guardrailprobe/)
[![Probes](https://img.shields.io/badge/Probes-78-green.svg)](guardrail_framework/probes.py)
[![Backends](https://img.shields.io/badge/Backends-11-blue.svg)](guardrail_framework/core.py)

---

## What it does

- **Fires 78 adversarial probes** — 58 OWASP LLM01–LLM10 attack probes + 20 content moderation probes (CM-001–CM-020 for hate speech, violence, sexual content, self-harm) — directly at your guardrail middleware, not the model
- **Compares 11 backends side-by-side** in a single run: NeMo Guardrails, GuardrailsAI, Presidio, Lakera Guard, GA Guard, OpenAI Moderation, Azure Content Safety, Azure Prompt Shields, AWS Bedrock Guardrails, LlamaFirewall, LLM Guard
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
# set GUARDRAIL_API_KEYS, GUARDRAIL_ADMIN_KEYS, and backend credentials
```

---

## Quickstart

```python
from guardrail_framework.red_team_runner import RedTeamRunner

runner = RedTeamRunner()

# Run all 78 probes against all configured backends
report = runner.compare_backends(
    backends=[
        # Local / no credentials
        "presidio", "guardrails_ai", "llama_firewall", "llm_guard",
        # OPENAI_API_KEY
        "nemo", "openai_moderation",
        # Cloud credentials
        "lakera", "ga_guard",
        "azure_content_safety", "azure_prompt_shields", "aws_bedrock",
    ],
)

print(f"Best overall:  {report.best_overall}")   # openai_moderation
print(f"Worst overall: {report.worst_overall}")  # guardrails_ai

# ┌─────────────────────────┬───────────┐
# │ backend                 │  overall  │
# ├─────────────────────────┼───────────┤
# │ openai_moderation       │  100.0 %  │
# │ nemo                    │   85.9 %  │
# │ llama_firewall          │   85.9 %  │
# │ llm_guard               │   85.9 %  │
# │ lakera                  │   83.3 %  │
# │ aws_bedrock             │   59.0 %  │
# │ azure_content_safety    │   25.6 %  │
# │ azure_prompt_shields    │   24.4 %  │
# │ presidio                │    6.4 %  │
# │ guardrails_ai           │    2.6 %  │
# └─────────────────────────┴───────────┘
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

| Backend                | PyPI package        | Notes                                                         |
| ---------------------- | ------------------- | ------------------------------------------------------------- |
| NeMo Guardrails        | `nemoguardrails`    | Colang-based rail config auto-compiled from policy            |
| GuardrailsAI           | `guardrails-ai`     | YAML rail config auto-compiled from policy                    |
| Microsoft Presidio     | `presidio-analyzer` | PII detection; falls back to regex if SDK absent              |
| LlamaFirewall          | `llamafirewall`     | Meta PromptGuard 2; fully local, no API key required          |
| LLM Guard              | `llm_guard`         | PromptInjection + Toxicity scanners; fully local, no API key  |
| Lakera Guard           | _(REST API)_        | Requires `LAKERA_GUARD_API_KEY`                               |
| GA Guard               | _(REST API)_        | Requires `GA_GUARD_API_URL` + `GA_GUARD_API_KEY`              |
| OpenAI Moderation      | _(REST API)_        | Requires `OPENAI_API_KEY`                                     |
| Azure Content Safety   | _(REST API)_        | Requires `AZURE_CONTENT_SAFETY_ENDPOINT` + `_KEY`             |
| Azure Prompt Shields   | _(REST API)_        | Same endpoint/key as Content Safety; detects prompt injection |
| AWS Bedrock Guardrails | `boto3`             | Requires `AWS_BEDROCK_GUARDRAIL_ID` + region                  |

All backends degrade gracefully to regex/keyword heuristics when the SDK is not installed, so you can start testing immediately without installing any optional dependency.

---

## Benchmark results

Latest run: **June 2026** — 78 probes × 11 backends ([live dashboard](https://askuma.github.io/guardrailprobe/) · [full report](docs/benchmarks/benchmark_2026_06.json))

| Backend                | Pass rate | Notes                                          |
| ---------------------- | :-------: | ---------------------------------------------- |
| OpenAI Moderation      |  100.0 %  | Best overall                                   |
| NeMo Guardrails        |  85.9 %   |                                                |
| LlamaFirewall          |  85.9 %   | Meta PromptGuard 2; fully local                |
| LLM Guard              |  85.9 %   | Local PromptInjection + Toxicity scanners      |
| Lakera Guard           |  83.3 %   |                                                |
| AWS Bedrock Guardrails |  59.0 %   |                                                |
| Azure Content Safety   |  25.6 %   |                                                |
| Azure Prompt Shields   |  24.4 %   |                                                |
| Microsoft Presidio     |   6.4 %   | PII-focused; weak on LLM01+                    |
| GuardrailsAI           |   2.6 %   | YAML rail config needed for full coverage      |

Pass rate = fraction of adversarial probes blocked or flagged by the backend. Higher is better. Results vary based on policy configuration — low scores for rule-engine backends (NeMo, GuardrailsAI, Presidio) reflect default/minimal policy configs, not inherent backend limits.

---

## Documentation

- [METHODOLOGY.md](METHODOLOGY.md) — Probe construction standard, OWASP mapping, pass/fail logic, report integrity, regulatory mapping (EU AI Act, GDPR, NIST AI RMF)
- [API_REFERENCE.md](API_REFERENCE.md) — All 55+ REST endpoints
- [SETUP_GUIDE.md](SETUP_GUIDE.md) — Production deployment, PostgreSQL, Redis, Docker
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to add probes, backends, and file issues
- [docs/benchmarks/](docs/benchmarks/) — Published benchmark reports (canonical location)

---

## Project layout

```
guardrail_framework/
  probes.py           — 78 built-in AttackProbe objects (58 OWASP LLM01–LLM10 + 20 CM probes)
  red_team_runner.py  — RedTeamRunner, ProbeResult, RedTeamReport, ComparisonReport
  report_signer.py    — PDF generation + PKCS#12 signing + RFC 3161 timestamp
  core.py             — GuardrailFramework, 11 backend adapters (incl. LlamaFirewall, LLM Guard), policy engine
  server.py           — FastAPI app, 55+ REST endpoints
  compiler.py         — Policy → Colang / YAML / Presidio config compiler
```

---

## Star this repo

If guardrailprobe saves your team an audit finding, drop a ⭐ — it helps others discover the project.

[github.com/askuma/guardrailprobe](https://github.com/askuma/guardrailprobe)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
