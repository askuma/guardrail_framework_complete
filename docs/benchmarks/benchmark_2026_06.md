# GuardrailProbe Benchmark — June 2026
> Independent OWASP LLM Top 10 + Content Moderation evaluation of AI guardrail backends.
> Methodology: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

## TL;DR
- **Winner:** openai_moderation (100.0% overall)
- **Best accuracy/latency ratio:** nemo
- **Biggest improvement vs last month:** none this month +0.0%
- **Biggest regression vs last month:** none this month -0.0%
- **Backends tested:** 9
- **Backends skipped:** 0
- **Total probes run:** 625
- **Report generated:** 2026-06-18 16:03 UTC
- **Run ID:** 2717ad31-ef65-4d13-b456-c52f92152154

---

## Overall Comparison

| Backend | Overall % | vs Last Month | Best Category | Worst Category | Avg Latency |
|---------|:---------:|:-------------:|:-------------:|:--------------:|:-----------:|
| nemo | 9.0% | — | LLM01 | LLM03 | 1 ms |
| guardrails_ai | 9.0% | — | LLM01 | LLM03 | 149 ms |
| presidio | 6.4% | — | LLM02 | LLM01 | 75 ms |
| lakera | 83.3% | — | LLM01 | LLM10 | 380 ms |
| ga_guard | 9.0% | — | LLM01 | LLM03 | 2 ms |
| openai_moderation | 100.0% | — | LLM01 | LLM01 | 32690 ms |
| azure_content_safety | 26.9% | — | LLM02 | LLM01 | 1653 ms |
| azure_prompt_shields | 24.4% | — | LLM01 | LLM09 | 780 ms |
| aws_bedrock | 59.0% | — | LLM01 | LLM10 | 914 ms |

---

## Per-Category Results (OWASP LLM Top 10)

| Category | Description | Winner | Score | Runner-up | Score |
|----------|-------------|:------:|:-----:|:---------:|:-----:|
| LLM01 | Prompt Injection | lakera | 100% | openai_moderation | 100% |
| LLM02 | Insecure Output | lakera | 81% | aws_bedrock | 76% |
| LLM03 | Training Data Poisoning | lakera | 100% | aws_bedrock | 100% |
| LLM04 | Model DoS | lakera | 67% | azure_content_safety | 33% |
| LLM05 | Supply Chain | lakera | 80% | azure_prompt_shields | 40% |
| LLM06 | Sensitive Info Disclosure | lakera | 100% | aws_bedrock | 50% |
| LLM07 | Insecure Plugin | lakera | 67% | nemo | 33% |
| LLM08 | Excessive Agency | lakera | 100% | aws_bedrock | 67% |
| LLM09 | Overreliance | lakera | 100% | aws_bedrock | 60% |
| LLM10 | Model Theft | lakera | 20% | nemo | 0% |

---

## Content Moderation Results

These probes test content moderation capabilities separate from adversarial attack detection.
Backends designed for content moderation (Azure Content Safety, OpenAI Moderation) are
expected to score higher here than on OWASP probes.

| Backend | Hate | Violence | Sexual | Self-Harm | Overall CM Score |
|---------|:----:|:--------:|:------:|:---------:|:----------------:|
| nemo | 0% | 0% | 0% | 0% | 0% |
| guardrails_ai | 0% | 0% | 0% | 0% | 0% |
| presidio | 0% | 0% | 0% | 0% | 0% |
| lakera | 100% | 100% | 100% | 100% | 100% |
| ga_guard | 0% | 0% | 0% | 0% | 0% |
| openai_moderation | 0% | 0% | 0% | 0% | 0% |
| azure_content_safety | 100% | 100% | 100% | 80% | 95% |
| azure_prompt_shields | 0% | 0% | 0% | 0% | 0% |
| aws_bedrock | 100% | 100% | 100% | 100% | 100% |

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
| nemo | 9.0% | 1 ms | Ultra-fast | Real-time inference, high-throughput pipelines |
| ga_guard | 9.0% | 2 ms | Ultra-fast | Real-time inference, high-throughput pipelines |
| presidio | 6.4% | 75 ms | Fast | Standard API protection |
| guardrails_ai | 9.0% | 149 ms | Fast | Standard API protection |
| lakera | 83.3% | 380 ms | Moderate | Batch processing, async pipelines |
| azure_prompt_shields | 24.4% | 780 ms | Moderate | Batch processing, async pipelines |
| aws_bedrock | 59.0% | 914 ms | Moderate | Batch processing, async pipelines |
| azure_content_safety | 26.9% | 1653 ms | Slow | Offline analysis, compliance audits |
| openai_moderation | 100.0% | 32690 ms | Slow | Offline analysis, compliance audits |

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
| LLM05 | high | 1 |
| LLM07 | critical | 1 |
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
