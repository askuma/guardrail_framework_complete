---
name: False positive report
about: A built-in probe incorrectly blocked benign input or flagged the wrong action
title: "[FP] <probe-id> — <one-line description>"
labels: false-positive, needs-triage
assignees: ""
---

## False Positive Report

A false positive occurs when a probe fires for input that should **not** be blocked,
or when the guardrail returns an unexpected action for a benign payload.

---

### Which probe triggered incorrectly

**Probe ID:** <!-- e.g. LLM01-003 -->

**Probe description:** <!-- copy from `lib.get_probe('LLM01-003').description` -->

---

### Which backend

<!-- Choose all that apply -->

- [ ] nemo (NeMo Guardrails)
- [ ] guardrails_ai (GuardrailsAI)
- [ ] presidio (Microsoft Presidio)
- [ ] lakera (Lakera Guard)
- [ ] ga_guard (GA Guard)
- [ ] regex fallback (no SDK installed)

**Backend version / config:**
<!-- e.g. nemoguardrails==0.8.1, sensitivity=medium -->

---

### Input that caused the false positive

```
<paste the exact input text here>
```

---

### Expected action vs actual action

| | Value |
|---|---|
| **Expected action** (probe's `expected_action`) | |
| **Actual action returned** | |
| **`passed` field in ProbeResult** | True / False |

---

### Reproduction steps

```python
from guardrail_framework.red_team_runner import RedTeamRunner

runner = RedTeamRunner()
report = runner.run_against_backend(backend="<backend>", probe_ids=["<probe-id>"])
result = report.probe_results[0]
print(result.passed, result.actual_action, result.error)
```

**Actual output:**

```
<paste output here>
```

---

### Why this is a false positive

<!-- Explain why the input is benign and should not be blocked, or why the
     returned action is incorrect for this probe's intent. -->

---

### Suggested fix

<!-- Optional. If you know which heuristic or regex is over-triggering, describe it.
     If proposing a payload change, note that built-in probe payloads are frozen
     (see METHODOLOGY.md §2 versioning policy) and a new probe ID may be needed. -->
