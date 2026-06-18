# GuardrailProbe Benchmark — June 2026
> Independent OWASP LLM Top 10 + Content Moderation evaluation of AI guardrail backends.
> Methodology: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

## TL;DR
- **Winner:** nemo (9.0% overall)
- **Best accuracy/latency ratio:** nemo
- **Biggest improvement vs last month:** none this month +0.0%
- **Biggest regression vs last month:** none this month -0.0%
- **Backends tested:** 3
- **Backends skipped:** 0
- **Total probes run:** 234
- **Report generated:** 2026-06-18 11:49 UTC
- **Run ID:** fd158288-2325-4ebd-8900-bfef33f97b3a

---

## Overall Comparison

| Backend | Overall % | vs Last Month | Best Category | Worst Category | Avg Latency |
|---------|:---------:|:-------------:|:-------------:|:--------------:|:-----------:|
| nemo | 9.0% | — | LLM01 | LLM03 | 1 ms |
| guardrails_ai | 9.0% | — | LLM01 | LLM03 | 61 ms |
| presidio | 6.4% | — | LLM02 | LLM01 | 50 ms |

---

## Per-Category Results (OWASP LLM Top 10)

| Category | Description | Winner | Score | Runner-up | Score |
|----------|-------------|:------:|:-----:|:---------:|:-----:|
| LLM01 | Prompt Injection | nemo | 43% | guardrails_ai | 43% |
| LLM02 | Insecure Output | presidio | 19% | nemo | 10% |
| LLM03 | Training Data Poisoning | nemo | 0% | guardrails_ai | 0% |
| LLM04 | Model DoS | nemo | 0% | guardrails_ai | 0% |
| LLM05 | Supply Chain | nemo | 0% | guardrails_ai | 0% |
| LLM06 | Sensitive Info Disclosure | nemo | 0% | guardrails_ai | 0% |
| LLM07 | Insecure Plugin | nemo | 33% | guardrails_ai | 33% |
| LLM08 | Excessive Agency | nemo | 0% | guardrails_ai | 0% |
| LLM09 | Overreliance | nemo | 0% | guardrails_ai | 0% |
| LLM10 | Model Theft | nemo | 0% | guardrails_ai | 0% |

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
| presidio | 6.4% | 50 ms | Fast | Standard API protection |
| guardrails_ai | 9.0% | 61 ms | Fast | Standard API protection |

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
| LLM01 | critical | 2 |
| LLM01 | high | 2 |
| LLM02 | high | 15 |
| LLM03 | critical | 3 |
| LLM03 | high | 2 |
| LLM04 | high | 3 |
| LLM04 | medium | 3 |
| LLM05 | critical | 4 |
| LLM05 | high | 1 |
| LLM06 | critical | 3 |
| LLM06 | high | 9 |
| LLM07 | critical | 3 |
| LLM08 | critical | 4 |
| LLM08 | high | 2 |
| LLM09 | critical | 1 |
| LLM09 | high | 3 |
| LLM09 | medium | 1 |
| LLM10 | high | 3 |
| LLM10 | medium | 2 |

> Full probe payloads are available to verified security researchers. Open an issue with
> label "researcher-access" to request access.

---

## Backends Skipped This Month

| Backend | Reason | Expected In |
|---------|--------|-------------|
| lakera | UNAVAILABLE | SDK not installed or API credentials not configured |
| ga_guard | UNAVAILABLE | SDK not installed or API credentials not configured |

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
