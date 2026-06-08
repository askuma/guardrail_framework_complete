# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | Yes — active development |
| 1.0.x   | Security fixes only |
| < 1.0   | No |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **security@yourorg.example.com** with:

1. A description of the vulnerability and the affected component
2. Steps to reproduce or a proof-of-concept (even partial is helpful)
3. Your assessment of the impact
4. Any suggested fix, if you have one

We will acknowledge receipt within **2 business days** and provide an initial assessment within **5 business days**. We aim to release a fix within **30 days** for confirmed critical/high issues.

Once fixed and released, we will credit you in the `CHANGELOG.md` (unless you prefer to remain anonymous).

## Threat Model

The Guardrail Framework is designed to be deployed as an internal service behind your application layer. The assumed threat model is:

- **Trusted callers**: your own services authenticating with a pre-shared API key
- **Untrusted content**: the text payloads passed through the guardrail (user-generated LLM inputs/outputs)
- **External backends**: Lakera, GA Guard — authenticated over HTTPS with API keys stored in environment variables, never logged

The framework **does not** protect against:
- Attackers with direct OS or network access to the host
- Compromised API keys (rotate them; use a secrets manager)
- Backend SDK vulnerabilities (report those to the respective vendors)

## Security Controls

### Authentication

All REST endpoints require an `X-API-Key` header. Configure keys via `GUARDRAIL_API_KEYS`.

Public (unauthenticated) paths are explicitly allowlisted and limited to:
- `/health`, `/ready` — liveness/readiness probes
- `/docs`, `/redoc`, `/openapi.json` — API documentation (disable in production if desired by setting `GUARDRAIL_DOCS_ENABLED=false`)
- `/metrics/prometheus` — Prometheus scrape; secure at the network level with firewall rules or a Prometheus basic-auth reverse proxy
- `/push/events` — SSE stream; the browser EventSource API cannot send custom headers, so authentication is enforced inside the route handler via a mandatory `?api_key=` query parameter

### Rate Limiting

Per-policy, per-user rate limiting is enforced. With Redis (`GUARDRAIL_REDIS_URL`), limits are consistent across multiple replicas. Without Redis, limits are per-process only.

Rate limiting fails **open** on Redis unavailability — outages do not block legitimate traffic.

### Data Handling

- API keys are never logged; only the count of loaded keys is logged at startup
- If `GUARDRAIL_API_KEYS` is unset, an ephemeral key is printed to **stderr** only (not to log shippers)
- External backend URLs are validated to reject private/loopback IP ranges before HTTP requests are made (`_validate_external_url`)
- Decision log and bundle poller auth tokens are accepted only over HTTPS endpoints (enforced by `_validate_external_url`)
- No user text is stored permanently; the audit log stores metadata (policy ID, risk score, action) but not the raw content by default

### Secrets Management

- Store secrets (`GUARDRAIL_API_KEYS`, `GUARDRAIL_DB_URL`, backend API keys) in a secrets manager (AWS Secrets Manager, HashiCorp Vault, Kubernetes Secrets) and inject as environment variables
- Never commit `.env` to source control — it is in `.gitignore`
- Rotate API keys regularly; the framework supports multiple simultaneous keys with no downtime

### Network

- Run behind a TLS-terminating reverse proxy (nginx, Caddy) in production — see [SETUP_GUIDE.md](SETUP_GUIDE.md#tls--https)
- Restrict `/metrics/prometheus` to your Prometheus server's IP at the load-balancer or firewall level
- Set `GUARDRAIL_CORS_ORIGINS` to your actual frontend origin(s) — do not use `*` in production

## Dependency Security

Dependencies are pinned with minimum versions in `requirements.txt`. Run `pip audit` or a dependency scanning tool (Dependabot, Snyk) to detect known CVEs in dependencies. Report findings there rather than here unless the vulnerability is in framework code itself.

## Known Accepted Trade-offs

| Item | Risk | Decision |
|------|------|----------|
| `?api_key=` in SSE URL | Key may appear in server access logs | Browser EventSource API constraint; mitigate with log scrubbing and short-lived keys |
| `/metrics/prometheus` unauthenticated | Stats visible to anyone on the network | Secure at network level; no secrets or PII are exposed |
| Rate limiting fails open on Redis loss | Limits not enforced during outage | Availability prioritised over rate enforcement; acceptable for internal services |
