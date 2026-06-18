# GuardrailProbe Benchmark — {MONTH} {YEAR}
> Independent OWASP LLM Top 10 + Content Moderation evaluation of AI guardrail backends.
> Methodology: github.com/askuma/guardrailprobe/blob/main/METHODOLOGY.md

---

## TL;DR
- **Winner:** {BEST_OVERALL_BACKEND} ({BEST_OVERALL_SCORE}% overall)
- **Best accuracy/latency ratio:** {RATIO_WINNER}
- **Biggest improvement vs last month:** {IMPROVEMENT_BACKEND} +{IMPROVEMENT_DELTA}%
- **Biggest regression vs last month:** {REGRESSION_BACKEND} -{REGRESSION_DELTA}%
- **Backends tested:** {BACKENDS_TESTED_COUNT}
- **Backends skipped:** {BACKENDS_SKIPPED_COUNT}
- **Total probes run:** {TOTAL_PROBES}
- **Report generated:** {GENERATED_AT}
- **Run ID:** {RUN_ID}

---

## Overall Comparison

| Backend | Overall % | vs Last Month | Best Category | Worst Category | Avg Latency |
|---------|:---------:|:-------------:|:-------------:|:--------------:|:-----------:|
{OVERALL_TABLE_ROWS}

---

## Per-Category Results (OWASP LLM Top 10)

| Category | Description | Winner | Score | Runner-up | Score |
|----------|-------------|:------:|:-----:|:---------:|:-----:|
| LLM01 | Prompt Injection | {LLM01_WINNER} | {LLM01_SCORE}% | {LLM01_SECOND} | {LLM01_SECOND_SCORE}% |
| LLM02 | Insecure Output | {LLM02_WINNER} | {LLM02_SCORE}% | {LLM02_SECOND} | {LLM02_SECOND_SCORE}% |
| LLM03 | Training Data Poisoning | {LLM03_WINNER} | {LLM03_SCORE}% | {LLM03_SECOND} | {LLM03_SECOND_SCORE}% |
| LLM04 | Model DoS | {LLM04_WINNER} | {LLM04_SCORE}% | {LLM04_SECOND} | {LLM04_SECOND_SCORE}% |
| LLM05 | Supply Chain | {LLM05_WINNER} | {LLM05_SCORE}% | {LLM05_SECOND} | {LLM05_SECOND_SCORE}% |
| LLM06 | Sensitive Info Disclosure | {LLM06_WINNER} | {LLM06_SCORE}% | {LLM06_SECOND} | {LLM06_SECOND_SCORE}% |
| LLM07 | Insecure Plugin | {LLM07_WINNER} | {LLM07_SCORE}% | {LLM07_SECOND} | {LLM07_SECOND_SCORE}% |
| LLM08 | Excessive Agency | {LLM08_WINNER} | {LLM08_SCORE}% | {LLM08_SECOND} | {LLM08_SECOND_SCORE}% |
| LLM09 | Overreliance | {LLM09_WINNER} | {LLM09_SCORE}% | {LLM09_SECOND} | {LLM09_SECOND_SCORE}% |
| LLM10 | Model Theft | {LLM10_WINNER} | {LLM10_SCORE}% | {LLM10_SECOND} | {LLM10_SECOND_SCORE}% |

---

## Content Moderation Results

These probes test content moderation capabilities separate from adversarial attack detection.
Backends designed for content moderation (Azure Content Safety, OpenAI Moderation) are
expected to score higher here than on OWASP probes.

| Backend | Hate | Violence | Sexual | Self-Harm | Overall CM Score |
|---------|:----:|:--------:|:------:|:---------:|:----------------:|
{CONTENT_MODERATION_TABLE_ROWS}

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
{LATENCY_TABLE_ROWS}

Latency categories:
- Ultra-fast: <10ms   (GA Guard)
- Fast: 10-200ms      (NeMo, Presidio, GuardrailsAI)
- Moderate: 200-1000ms (Lakera, AWS Bedrock)
- Slow: 1000ms+        (OpenAI, Azure)

---

## Notable Bypasses

Attack patterns that bypassed ALL tested backends this month. These represent current gaps
in the guardrail ecosystem.

{NOTABLE_BYPASSES_LIST}

> Full probe payloads are available to verified security researchers. Open an issue with
> label "researcher-access" to request access.

---

## Backends Skipped This Month

| Backend | Reason | Expected In |
|---------|--------|-------------|
{SKIPPED_BACKENDS_TABLE}

---

## Month-over-Month Changes

{DELTA_SECTION}

---

## How to Reproduce This Benchmark

```bash
pip install guardrailprobe

python3 benchmark_report.py \
  --year {YEAR} \
  --month {MONTH} \
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
or Amazon. Results reflect probe library v{VERSION} against backend configurations at time
of testing.*
