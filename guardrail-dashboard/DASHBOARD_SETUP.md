# Guardrail Dashboard — Setup Guide

## What you get

A live React dashboard at `http://localhost:3000` that talks to the FastAPI
backend at `http://localhost:8000`.  Ten tabs:

| Tab | What it shows |
|-----|--------------|
| 📊 Overview   | KPIs, check-volume chart, action breakdown pie, backend bar chart |
| 🧪 Live Test  | Type text, pick a policy, run input/output checks in real time |
| 📋 Policies   | Create / delete policies; one-click templates |
| ✅ Testing    | Run the built-in adversarial smoke suite against a policy (Gap 1) |
| 💓 Status     | Per-policy health, error rates, p95 latency, blocklist control (Gaps 8/9/11) |
| 🗂 Versions   | Snapshot history + one-click rollback, bundle export (Gaps 4/5) |
| 🚨 Alerts     | Active alerts, resolve button, auto-refreshes every 10 s |
| 🔀 A/B Tests  | Create tests, simulate traffic assignment |
| 📜 Audit Log  | Every guardrail check, searchable, sortable |
| 🔴 Red Team   | Fire 78 OWASP LLM01–LLM10 probes across all 11 backends simultaneously; compare results side-by-side |

The header shows a live ⚡ indicator whenever a policy-change event arrives over
the Server-Sent Events stream (Gap 6) — the dashboard auto-refreshes on every change.

### 🔴 Red Team tab — detailed features

**Visual scan progress overlay** — while a run is active, a full-screen progress panel
shows a live probe counter, current OWASP category, and per-backend pass/fail tally
in real time.  The overlay dismisses automatically when all probes complete.

**Comparison table** — results are grouped into two sections:
- **General Purpose Guardrails** (NeMo, Lakera, GA Guard, Azure Content Safety, AWS Bedrock, LlamaFirewall, LLM Guard)
- **Specialized Tools** (GuardrailsAI, Presidio, OpenAI Moderation, Azure Prompt Shields)

Each row shows overall pass rate, per-OWASP-category (LLM01–LLM10) pass rates, and average
latency. ★ marks the category winner; ⚠ flags backends where fewer than 50 % of probes ran.
A footnote block explains each symbol (identical to the published GitHub Pages report).

**Persistent run history** — each completed comparison run is saved in browser storage and
listed in a collapsible panel below the live table.  You can re-open any past run to review
its results without re-firing probes.

---

## Prerequisites

| Tool | Min version | Check |
|------|-------------|-------|
| Python | 3.9 | `python --version` |
| Node.js | 18 | `node --version` |
| npm | 9 | `npm --version` |

---

## Step 1 — Start the API backend

```bash
cd guardrail_framework_complete/   # your extracted ZIP

# Install Python deps
pip install -r requirements.txt

# Start FastAPI
uvicorn guardrail_framework.server:app --host 0.0.0.0 --port 8000 --reload
```

Verify it works:
```bash
curl http://localhost:8000/health
# {"status":"ok","policies_loaded":0,...}
```

The interactive API docs are at **http://localhost:8000/docs**

---

## Step 2 — Install the dashboard

```bash
cd guardrail-dashboard/

npm install        # installs React, Recharts, etc. (~1 min)
```

---

## Step 3 — Start the dashboard

```bash
npm start
```

Browser opens automatically at **http://localhost:3000**

The dashboard auto-proxies API calls to `:8000` (configured in package.json).

---

## Step 4 — Load some data

Everything is empty until you create policies and run checks. Two options:

### Option A — Click through the UI
1. Go to **📋 Policies** tab → click a template button (e.g. "balanced")
2. Go to **🧪 Live Test** tab → pick the policy → type some text → click "Run check"
3. Watch **📊 Overview** and **📜 Audit Log** update

### Option B — Run the examples script
```bash
# In a separate terminal, from the extracted ZIP folder:
python -m guardrail_framework.examples
```

Then refresh the dashboard — the Overview and Audit Log will populate.

---

## Environment variables (optional)

| Variable | Default | Purpose |
|----------|---------|---------|
| `REACT_APP_API_URL` | `''` (proxy) | Override API base URL |
| `PORT` | `3000` | Dashboard port |

To point the dashboard at a remote API:
```bash
REACT_APP_API_URL=https://your-api.example.com npm start
```

---

## Production build (static files)

```bash
npm run build
```

Outputs to `build/` — serve with nginx, Caddy, or any static host.

Minimal nginx config:
```nginx
server {
    listen 80;

    location / {
        root /var/www/guardrail-dashboard/build;
        try_files $uri /index.html;
    }

    location /api/ {
        proxy_pass http://localhost:8000/;
    }
}
```

---

## Docker (optional — runs both services together)

```bash
# From the project root
docker-compose up --build
```

`docker-compose.yml`:
```yaml
version: "3.9"
services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    ports: ["8000:8000"]

  dashboard:
    build:
      context: ./guardrail-dashboard
      dockerfile: Dockerfile.dashboard
    ports: ["3000:80"]
    environment:
      - REACT_APP_API_URL=http://localhost:8000
    depends_on: [api]
```

`guardrail-dashboard/Dockerfile.dashboard`:
```dockerfile
FROM node:18-alpine AS build
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
EXPOSE 80
```

---

## Troubleshooting

### Dashboard shows "API Offline"
- Is `uvicorn` running?  Check `curl http://localhost:8000/health`
- Wrong port?  Set `REACT_APP_API_URL=http://localhost:YOUR_PORT`

### CORS errors in browser console
The FastAPI server already has `allow_origins=["*"]`.
If you're hitting a different domain, ensure the server's CORS config matches.

### `npm install` fails
```bash
node --version   # must be ≥ 18
npm cache clean --force
npm install
```

### Blank page after `npm start`
```bash
# Check for errors
npm start 2>&1 | head -40
```

### Port 3000 already in use
```bash
PORT=3001 npm start
```
