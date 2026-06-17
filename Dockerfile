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

# System deps (gosu for safe root→guardrail privilege drop at runtime)
RUN apt-get update && apt-get install -y --no-install-recommends curl gosu \
    && rm -rf /var/lib/apt/lists/*

# Python deps (cached layer)
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install the framework package
COPY guardrail_framework/ ./guardrail_framework/
COPY setup.py .
RUN pip install --no-cache-dir -e .

# Copy the compiled React app from stage 1
COPY --from=dashboard-build /dashboard/build ./guardrail_framework/static/

# Patch server.py to serve the React build — APPENDS static routes LAST so the
# SPA catch-all never shadows the API routes (/health, /status, /metrics, ...)
COPY patch_static.py .
RUN python patch_static.py

# Non-root user
RUN useradd -m -u 1000 guardrail && chown -R guardrail:guardrail /app

# Create data directory for SQLite database (entrypoint re-chowns at runtime
# to handle stale named volumes that may be root-owned from older images)
RUN mkdir -p /app/data && chown -R guardrail:guardrail /app/data

# Entrypoint: runs as root, fixes /app/data ownership, then drops to guardrail
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# API + Dashboard on the same port
EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "guardrail_framework.server:app", \
    "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
