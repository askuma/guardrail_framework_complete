# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Build React dashboard
# ─────────────────────────────────────────────────────────────────────────────
FROM node:18-alpine AS dashboard-build

WORKDIR /dashboard

COPY guardrail-dashboard/package.json .
RUN npm install --silent

COPY guardrail-dashboard/public/ ./public/
COPY guardrail-dashboard/src/    ./src/

ENV REACT_APP_API_URL=""
RUN npm run build


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Python API + serve built dashboard as static files
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="Enterprise AI Safety Team"
LABEL description="Guardrail Framework – API + React Dashboard (single container)"

WORKDIR /app

# System deps.  gcc / g++ / libffi-dev / libssl-dev are required to compile
# packages with C extensions (cryptography → pyhanko, uvloop, httptools).
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Python deps (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir \
        "opentelemetry-exporter-otlp-proto-grpc<1.27.0" \
        "opentelemetry-exporter-otlp-proto-common<1.27.0"

# Install the framework package
COPY guardrail_framework/ ./guardrail_framework/
COPY pyproject.toml README.md LICENSE benchmark_report.py ./
RUN pip install --no-cache-dir -e .

# Install spaCy + Presidio and download the NLP model for PII detection.
# spacy / presidio are optional in requirements.txt (local dev); they are
# always installed in the container image so Presidio runs at full accuracy.
RUN pip install --no-cache-dir \
    "spacy>=3.0.0" \
    "presidio-analyzer>=2.2.0" \
    "presidio-anonymizer>=2.2.0" \
    && python -m spacy download en_core_web_lg

# Install GuardrailsAI hub validators so the backend runs real validation
# instead of the regex-only fallback.
#
#   DetectPII     — finds PII in inputs/outputs using presidio (already present)
#   SecretsPresent — detects API keys / tokens using detect-secrets
#
# Both are free validators that require no GUARDRAILS_TOKEN.
# The || true makes each step non-fatal so a network outage during build does
# not break the image; the backend falls back to the regex scorer gracefully.
RUN pip install --no-cache-dir detect-secrets && \
    guardrails hub install hub://guardrails/detect_pii --quiet 2>/dev/null || true && \
    guardrails hub install hub://guardrails/secrets_present --quiet 2>/dev/null || true && \
    pip cache purge 2>/dev/null || true

# Copy the compiled React app from stage 1
COPY --from=dashboard-build /dashboard/build ./guardrail_framework/static/

# Patch server.py to serve the React build
COPY patch_static.py .
RUN python patch_static.py

# Create persistent data directories
RUN mkdir -p /app/data /app/docs/benchmarks

# Entrypoint script — configures guardrails hub access when GUARDRAILS_TOKEN is set.
# Must be copied and chmod'd before USER switch so root can write to /app.
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Re-pin the entire OTel exporter family after guardrails hub installs.
# Hub install spawns pip internally and can float proto-http, proto-grpc, and
# proto-common independently above 1.27.0.  All three must be at the same major
# version: proto-http>=1.27.0 imports _exporter_metrics from proto-common, but
# guardrails-ai requires proto-common<1.27.0 (the module lives there).
# This pin must be the last pip operation so nothing can undo it.
RUN pip install --no-cache-dir \
        "opentelemetry-exporter-otlp-proto-http<1.27.0" \
        "opentelemetry-exporter-otlp-proto-grpc<1.27.0" \
        "opentelemetry-exporter-otlp-proto-common<1.27.0" && \
    pip cache purge 2>/dev/null || true && \
    find /usr/local/lib/python3.11 -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# Non-root user
RUN useradd -m -u 1000 guardrail && \
    mkdir -p /app/hf_models && \
    chown -R guardrail:guardrail /app /app/data /app/docs/benchmarks /app/hf_models

# Append /app/site-packages via a .pth file so Python finds llamafirewall and
# llm-guard (bind-mounted from the host) WITHOUT letting their bundled copies of
# shared packages (opentelemetry, grpcio, …) shadow the versions already
# installed in system site-packages that guardrails-ai depends on.
# PYTHONPATH prepends (overrides); .pth appends (fallback) — that's what we want.
RUN echo "/app/site-packages" >> /usr/local/lib/python3.11/site-packages/app_extras.pth

USER guardrail

# HuggingFace model cache — bind-mounted from ./hf_models on the host so
# models persist across rebuilds and never bloat the image layers.
ENV HF_HOME=/app/hf_models

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "guardrail_framework.server:app", \
    "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
