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
COPY setup.py .
RUN pip install --no-cache-dir -e .

# Install spaCy + Presidio and download the NLP model for PII detection.
# spacy / presidio are optional in requirements.txt (local dev); they are
# always installed in the container image so Presidio runs at full accuracy.
RUN pip install --no-cache-dir \
    "spacy>=3.0.0" \
    "presidio-analyzer>=2.2.0" \
    "presidio-anonymizer>=2.2.0" \
    && python -m spacy download en_core_web_lg

# Copy the compiled React app from stage 1
COPY --from=dashboard-build /dashboard/build ./guardrail_framework/static/

# Patch server.py to serve the React build
COPY patch_static.py .
RUN python patch_static.py

# Create data directory for SQLite database
RUN mkdir -p /app/data

# Non-root user
RUN useradd -m -u 1000 guardrail && chown -R guardrail:guardrail /app
RUN chown -R guardrail:guardrail /app/data

USER guardrail

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "guardrail_framework.server:app", \
     "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
