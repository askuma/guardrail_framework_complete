# GuardrailProbe Benchmark — June 2026
> Independent OWASP LLM Top 10 + Content Moderation evaluation of AI guardrail backends.
> Methodology: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

## TL;DR
- **Winner:** nemo (85.9% overall)
- **Best accuracy/latency ratio:** llama_firewall
- **Biggest improvement vs last month:** none this month +0.0%
- **Biggest regression vs last month:** none this month -0.0%
- **Backends tested:** 10
- **Backends skipped:** 0
- **Total probes run:** 703
- **Report generated:** 2026-06-23 05:00 UTC
- **Run ID:** c7a02099-e0a2-46ae-aa4b-c6b8903139e5

---

## Overall Comparison

| Backend | Overall % | vs Last Month | Best Category | Worst Category | Avg Latency |
|---------|:---------:|:-------------:|:-------------:|:--------------:|:-----------:|
| nemo | 85.9% | — | LLM01 | LLM10 | 1505 ms |
| guardrails_ai | 2.6% | — | LLM07 | LLM01 | 183 ms |
| presidio | 6.4% | — | LLM02 | LLM01 | 1578 ms |
| lakera | 83.3% | — | LLM01 | LLM10 | 543 ms |
| openai_moderation | 100.0% | — | LLM01 | LLM01 | 35058 ms |
| azure_content_safety | 25.6% | — | LLM02 | LLM01 | 1124 ms |
| azure_prompt_shields | 24.4% | — | LLM01 | LLM09 | 1427 ms |
| aws_bedrock | 59.0% | — | LLM01 | LLM10 | 920 ms |
| llama_firewall | 85.9% | — | LLM01 | LLM10 | 79 ms |
| llm_guard | 85.9% | — | LLM01 | LLM10 | 351 ms |

---

## Per-Category Results (OWASP LLM Top 10)

| Category | Description | Winner | Score | Runner-up | Score |
|----------|-------------|:------:|:-----:|:---------:|:-----:|
| LLM01 | Prompt Injection | nemo | 100% | lakera | 100% |
| LLM02 | Insecure Output | nemo | 81% | lakera | 81% |
| LLM03 | Training Data Poisoning | nemo | 100% | lakera | 100% |
| LLM04 | Model DoS | nemo | 67% | lakera | 67% |
| LLM05 | Supply Chain | nemo | 100% | llama_firewall | 100% |
| LLM06 | Sensitive Info Disclosure | nemo | 100% | lakera | 100% |
| LLM07 | Insecure Plugin | nemo | 83% | llama_firewall | 83% |
| LLM08 | Excessive Agency | nemo | 100% | lakera | 100% |
| LLM09 | Overreliance | nemo | 100% | lakera | 100% |
| LLM10 | Model Theft | nemo | 20% | lakera | 20% |

---

## Content Moderation Results

These probes test content moderation capabilities separate from adversarial attack detection.
Backends designed for content moderation (Azure Content Safety, OpenAI Moderation) are
expected to score higher here than on OWASP probes.

| Backend | Hate | Violence | Sexual | Self-Harm | Overall CM Score |
|---------|:----:|:--------:|:------:|:---------:|:----------------:|
| nemo | 100% | 100% | 100% | 100% | 100% |
| guardrails_ai | 0% | 0% | 0% | 0% | 0% |
| presidio | 0% | 0% | 0% | 0% | 0% |
| lakera | 100% | 100% | 100% | 100% | 100% |
| openai_moderation | 0% | 0% | 0% | 0% | 0% |
| azure_content_safety | 100% | 100% | 100% | 80% | 95% |
| azure_prompt_shields | 0% | 0% | 0% | 0% | 0% |
| aws_bedrock | 100% | 100% | 100% | 100% | 100% |
| llama_firewall | 100% | 100% | 100% | 100% | 100% |
| llm_guard | 100% | 100% | 100% | 100% | 100% |

---

## Backend Capability Matrix

Use this matrix to understand what each backend is designed to detect. A low OWASP score
does not mean a backend is poor — it may be optimized for a different threat category.

| Backend | Prompt Injection | Jailbreak | Content Moderation | PII Detection | Hallucination | Agentic Safety |
|---------|:---------------:|:---------:|:------------------:|:-------------:|:-------------:|:--------------:|
| NeMo Guardrails | ✓ Primary | ✓ | ✗ | ✗ | ✗ | ✓ |
| GuardrailsAI | ✓ | ✓ | ✗ | ✓ | ✓ | ✗ |
| Presidio | ✗ | ✗ | ✗ | ✓ Primary | ✗ | ✗ |
| Lakera Guard | ✓ Primary | ✓ | ✗ | ✗ | ✗ | ✗ |
| GA Guard | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| OpenAI Moderation | ✗ | ✓ | ✓ Primary | ✗ | ✗ | ✗ |
| Azure Content Safety | ✗ | ✗ | ✓ Primary | ✗ | ✗ | ✗ |
| Azure Prompt Shields | ✓ Primary | ✓ | ✗ | ✗ | ✗ | ✗ |
| AWS Bedrock | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |

> ✓ Primary = this is the backend's core strength
> ✓ = supported capability
> ✗ = not designed for this threat category

---

## Accuracy vs Latency Tradeoff

Key insight: high accuracy and low latency are in tension. Choose your backend based on
your latency budget.

| Backend | Overall % | Avg Latency | Latency Category | Recommended For |
|---------|:---------:|:-----------:|:----------------:|-----------------|
| llama_firewall | 85.9% | 79 ms | Fast | Standard API protection |
| guardrails_ai | 2.6% | 183 ms | Fast | Standard API protection |
| llm_guard | 85.9% | 351 ms | Moderate | Batch processing, async pipelines |
| lakera | 83.3% | 543 ms | Moderate | Batch processing, async pipelines |
| aws_bedrock | 59.0% | 920 ms | Moderate | Batch processing, async pipelines |
| azure_content_safety | 25.6% | 1124 ms | Slow | Offline analysis, compliance audits |
| azure_prompt_shields | 24.4% | 1427 ms | Slow | Offline analysis, compliance audits |
| nemo | 85.9% | 1505 ms | Slow | Offline analysis, compliance audits |
| presidio | 6.4% | 1578 ms | Slow | Offline analysis, compliance audits |
| openai_moderation | 100.0% | 35058 ms | Slow | Offline analysis, compliance audits |

Latency categories:
- Ultra-fast: <10ms   (GA Guard)
- Fast: 10-200ms      (NeMo, Presidio, GuardrailsAI)
- Moderate: 200-1000ms (Lakera, AWS Bedrock)
- Slow: 1000ms+        (OpenAI, Azure)

---

## Notable Bypasses

Attack patterns that bypassed ALL tested backends this month. These represent current gaps
in the guardrail ecosystem.

| OWASP Category | Severity | Count |
|:---------------|:--------:|:-----:|
| LLM04 | high | 1 |
| LLM04 | medium | 1 |
| LLM10 | high | 3 |
| LLM10 | medium | 1 |

> Full probe payloads are available to verified security researchers. Open an issue with
> label "researcher-access" to request access.

---

## Backends Skipped This Month

| Backend | Reason | Expected In |
|---------|--------|-------------|
| — | — | — |

---

## Month-over-Month Changes

First benchmark — no prior month comparison available.

---

## How to Reproduce This Benchmark

```bash
pip install guardrailprobe

python3 benchmark_report.py \
  --year 2026 \
  --month June \
  --dry-run
```

Full reproduction guide: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

## About This Benchmark

GuardrailProbe is an independent, open-source AI guardrail testing framework with no
commercial relationship to any tested backend.

Probe library, methodology, and scoring logic are fully open source and independently
auditable.

- GitHub: github.com/askuma/guardrailprobe
- PyPI: pypi.org/project/guardrailprobe
- Methodology: METHODOLOGY.md
- Report an issue: GitHub Issues

---
*GuardrailProbe is not affiliated with NVIDIA, Microsoft, OpenAI, Lakera, General Analysis,
or Amazon. Results reflect probe library v0.1.0 against backend configurations at time
of testing.*
