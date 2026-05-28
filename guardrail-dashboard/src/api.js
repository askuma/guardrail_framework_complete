// src/api.js  —  thin client wrapping every FastAPI endpoint

const BASE = process.env.REACT_APP_API_URL || '';   // '' → uses CRA proxy to :8000

async function req(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || res.statusText);
  }
  return res.json();
}

export const api = {
  // ── System ──────────────────────────────────────────
  health:           () => req('GET',  '/health'),

  // ── Policies ────────────────────────────────────────
  listPolicies:     ()         => req('GET',    '/policies'),
  getPolicy:        (id)       => req('GET',    `/policies/${id}`),
  createPolicy:     (body)     => req('POST',   '/policies', body),
  updatePolicy:     (id, body) => req('PATCH',  `/policies/${id}`, body),
  deletePolicy:     (id)       => req('DELETE', `/policies/${id}`),
  exportPolicy:     (id, fmt)  => req('GET',    `/policies/${id}/export?format=${fmt}`),
  listTemplates:    ()         => req('GET',    '/policies/templates/list'),
  createFromTemplate: (name)   => req('POST',   `/policies/templates/${name}`),

  // ── Guardrail checks ────────────────────────────────
  checkInput:  (body) => req('POST', '/check/input',  body),
  checkOutput: (body) => req('POST', '/check/output', body),
  checkTool:   (body) => req('POST', '/check/tool',   body),

  // ── A/B Tests ───────────────────────────────────────
  listABTests:   ()       => req('GET',  '/abtests'),
  createABTest:  (body)   => req('POST', '/abtests', body),
  assignABTest:  (id)     => req('GET',  `/abtests/${id}/assign`),

  // ── Observability ───────────────────────────────────
  getMetrics:    () => req('GET', '/metrics'),
  getDashboard:  () => req('GET', '/metrics/dashboard'),
  getAuditLog:   (limit = 50) => req('GET', `/audit?limit=${limit}`),
  getAlerts:     () => req('GET', '/alerts'),
  resolveAlert:  (id) => req('DELETE', `/alerts/${id}`),

  // ── Schema ──────────────────────────────────────────
  getBackends:    () => req('GET', '/schema/backends'),
  getRiskCats:    () => req('GET', '/schema/risk-categories'),
  getActions:     () => req('GET', '/schema/actions'),
};
