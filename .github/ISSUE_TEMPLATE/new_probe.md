---
name: New probe
about: Propose a new adversarial probe for the built-in library
title: "[PROBE] LLM{NN}-{NNN} — <one-line description>"
labels: probe, needs-review
assignees: ""
---

## New Probe Proposal

> Before filling this out, read the [probe quality checklist](../../CONTRIBUTING.md#2-probe-quality-checklist)
> and confirm your probe doesn't duplicate an existing one:
> `grep -F 'your payload text' guardrail_framework/probes.py`

---

### Probe ID suggestion

<!-- Format: LLM{NN}-{NNN} where NN = OWASP category, NNN = next sequential number.
     Run the ID finder in CONTRIBUTING.md §1 to get the right next number. -->

**Suggested ID:**

---

### OWASP category

<!-- Choose exactly one -->

- [ ] LLM01 — Prompt Injection
- [ ] LLM02 — Insecure Output Handling
- [ ] LLM03 — Training Data Poisoning
- [ ] LLM04 — Model Denial of Service
- [ ] LLM05 — Supply Chain Vulnerabilities
- [ ] LLM06 — Sensitive Information Disclosure
- [ ] LLM07 — Insecure Plugin Design
- [ ] LLM08 — Excessive Agency
- [ ] LLM09 — Overreliance
- [ ] LLM10 — Model Theft

---

### Attack payload

<!-- Paste the exact text that would be submitted to the guardrail as input.
     Keep it to a single string; if the attack requires multi-turn context,
     note that in the "Technique" section below. -->

```
<paste payload here>
```

---

### Why current backends miss it

<!-- Explain what property of this payload causes it to evade the default
     regex/keyword heuristics and/or any known backend SDK.
     Be specific: "the pattern disguises the injection using Unicode lookalike
     characters, which the Presidio regex set does not normalise." -->

---

### Severity justification

<!-- Choose one and explain why -->

- [ ] `critical` — complete safety bypass; attack reaches the model unmodified
- [ ] `high` — targeted bypass of a specific guardrail category
- [ ] `medium` — succeeds against weak configurations; blocked by strict settings
- [ ] `low` — edge case; relevant for defence-in-depth

**Justification:**

---

### Proposed `expected_action`

- [ ] `block`
- [ ] `allow` (benign canary — false-positive test)

---

### Proposed tags (at least 2)

<!-- Use established vocabulary from CONTRIBUTING.md or propose new ones -->

---

### Additional context

<!-- Relevant CVEs, research papers, real-world incidents, or PoC links -->
