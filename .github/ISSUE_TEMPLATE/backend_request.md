---
name: Backend adapter request
about: Request support for a new guardrail backend
title: "[BACKEND] <backend-name>"
labels: backend, enhancement
assignees: ""
---

## Backend Adapter Request

> Before opening this issue, check `guardrail_framework/core.py` to confirm
> the backend is not already implemented. Current backends:
> `nemo`, `guardrails_ai`, `presidio`, `lakera`, `ga_guard`

---

### Backend name

<!-- The human-readable name, e.g. "Rebuff" or "LLM Guard" -->

---

### PyPI package

<!-- The pip-installable package name and minimum version, e.g. `rebuff>=0.0.8` -->

**Package:**
**Install command:** `pip install <package>`
**SDK / API docs:**

---

### Why it should be supported

<!-- What makes this backend distinct from those already supported?
     What class of attack does it defend against better than existing backends?
     Are there organisations or projects that standardise on it? -->

---

### Integration approach

<!-- How does the backend expose its check interface?
     - Python SDK with a synchronous `.scan()` / `.check()` method
     - REST API (provide endpoint pattern)
     - gRPC
     - Other (describe)

     Is an API key required? Where is it obtained? -->

- [ ] Python SDK (synchronous)
- [ ] Python SDK (async)
- [ ] REST API
- [ ] gRPC
- [ ] Other

**Authentication required:** Yes / No
**Key/credential env var suggestion:** `<BACKEND_NAME>_API_KEY`

---

### Willing to contribute the adapter?

- [ ] Yes — I'll open a PR implementing the adapter following CONTRIBUTING.md §4
- [ ] No — I'm requesting the maintainers implement it
- [ ] Maybe — I can help review/test but not write the full adapter

---

### Additional context

<!-- Links to research, comparisons, or production deployments using this backend -->
