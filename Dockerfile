# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Build React dashboard
# ─────────────────────────────────────────────────────────────────────────────
FROM node:18-alpine AS dashboard-build

WORKDIR /dashboard

# Install JS dependencies (cached layer)
COPY guardrail-dashboard/package.json .
RUN npm install --silent

# Copy source and build
COPY guardrail-dashboard/public/ ./public/
COPY guardrail-dashboard/src/    ./src/

# Same-origin: dashboard and API served from the same port, so empty base URL
ENV REACT_APP_API_URL=""
RUN npm run build


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Python API + serve built dashboard as static files
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="Enterprise AI Safety Team"
LABEL description="Guardrail Framework – API + React Dashboard (single container)"

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Python deps (cached layer)
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install the framework package
COPY guardrail_framework/ ./guardrail_framework/
COPY setup.py .
RUN pip install --no-cache-dir -e .

# Download spaCy model for Presidio PII detection
RUN python -m spacy download en_core_web_lg

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
