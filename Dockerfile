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
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

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
    guardrails hub install hub://guardrails/secrets_present --quiet 2>/dev/null || true

# Pre-warm the tldextract public-suffix list into a fixed cache directory so
# the container doesn't need outbound DNS at runtime.  TLDEXTRACT_CACHE_DIR is
# exported into the image and picked up automatically when Python code calls
# tldextract.  The || true ensures a build-time network failure is non-fatal
# (tldextract will fall back to its bundled snapshot).
ENV TLDEXTRACT_CACHE_DIR=/app/tldextract_cache
RUN mkdir -p /app/tldextract_cache && \
    python3 -c "import tldextract; tldextract.extract('example.com')" 2>/dev/null || true

# Copy the compiled React app from stage 1
COPY --from=dashboard-build /dashboard/build ./guardrail_framework/static/

# Patch server.py to serve the React build
COPY patch_static.py .
RUN python patch_static.py

# Create persistent data directories
RUN mkdir -p /app/data /app/docs/benchmarks

# Entrypoint script — installs premium GuardrailsAI hub validators at container
# start when GUARDRAILS_TOKEN is set (ToxicLanguage for LLM01 coverage).
# Must be copied and chmod'd before USER switch so root can write to /app.
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Non-root user
RUN useradd -m -u 1000 guardrail && \
    chown -R guardrail:guardrail /app /app/tldextract_cache /app/data /app/docs/benchmarks

USER guardrail

# LlamaFirewall and LLM Guard installed as the non-root guardrail user.
# pip --user writes to ~/.local/lib/python3.11/site-packages/ (no root required).
# Pre-warm pulls models from HuggingFace; || true keeps the build non-fatal if
# the network is unavailable at build time.
ENV PATH="/home/guardrail/.local/bin:${PATH}"
RUN pip install --user --no-cache-dir "llamafirewall>=0.1.0" "llm-guard>=0.3.13" && \
    python3 -c "import asyncio; from llamafirewall import LlamaFirewall, UserMessage; asyncio.run(LlamaFirewall().scan(UserMessage(content='test')))" 2>/dev/null || true && \
    python3 -c "from llm_guard.input_scanners import PromptInjection, Toxicity; PromptInjection(); Toxicity()" 2>/dev/null || true

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "guardrail_framework.server:app", \
    "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
