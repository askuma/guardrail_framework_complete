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

# Point the dashboard at the API on the same origin (no CORS needed)
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

# Copy the compiled React app from stage 1
COPY --from=dashboard-build /dashboard/build ./guardrail_framework/static/

# Patch server.py to also serve the React static build
RUN python - << 'PYEOF'
import re, pathlib

path = pathlib.Path("guardrail_framework/server.py")
src  = path.read_text()

# Only patch once
if "StaticFiles" not in src:
    # 1. Add StaticFiles / HTMLResponse imports after the fastapi import line
    src = src.replace(
        "from fastapi import FastAPI, HTTPException, Request",
        "from fastapi import FastAPI, HTTPException, Request\n"
        "from fastapi.staticfiles import StaticFiles\n"
        "from fastapi.responses import HTMLResponse",
    )

    # 2. Mount static assets and catch-all for React Router — insert after CORS middleware
    mount_snippet = '''
# ── Serve compiled React dashboard ────────────────────────────────────────────
import os as _os
_static_dir = _os.path.join(_os.path.dirname(__file__), "static")
if _os.path.isdir(_static_dir):
    app.mount("/static", StaticFiles(directory=_os.path.join(_static_dir, "static")), name="assets")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/{full_path:path}", response_class=HTMLResponse, include_in_schema=False)
    def serve_react(full_path: str = ""):
        # Let API routes take priority; only serve index.html for unknown paths
        index = _os.path.join(_static_dir, "index.html")
        if _os.path.exists(index):
            return HTMLResponse(open(index).read())
        return HTMLResponse("<h1>Dashboard not found</h1>", status_code=404)
# ──────────────────────────────────────────────────────────────────────────────
'''
    # Insert AFTER all API routes, just before the entry point
    # This ensures concrete API routes always take priority over the SPA catch-all
    src = src.replace(
        "# ─── Entry point ──────────────────────────────────────────────────────────────",
        mount_snippet + "# ─── Entry point ──────────────────────────────────────────────────────────────",
    )
    path.write_text(src)
    print("server.py patched OK")
else:
    print("server.py already patched — skipping")
PYEOF

# Non-root user
RUN useradd -m -u 1000 guardrail && chown -R guardrail:guardrail /app
USER guardrail

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# API  +  Dashboard on the same port
EXPOSE 8000

CMD ["uvicorn", "guardrail_framework.server:app", \
     "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]
