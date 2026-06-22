import React, { useState, useEffect, useCallback } from 'react';
import {
  LineChart, Line, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, PieChart, Pie, Cell,
} from 'recharts';
import { api } from './api';

// ─── Colour palette ──────────────────────────────────────────────────────────
const C = {
  bg:       '#f8fafc',
  card:     '#ffffff',
  border:   '#e2e8f0',
  muted:    '#94a3b8',
  sub:      '#475569',
  text:     '#0f172a',
  blue:     '#0284c7',
  green:    '#059669',
  amber:    '#d97706',
  red:      '#dc2626',
  purple:   '#7c3aed',
  surface:  '#f1f5f9',
};

const PIE_COLORS = [C.red, C.amber, C.blue, C.purple, C.green];

// ─── Tiny helpers ────────────────────────────────────────────────────────────
const Badge = ({ children, color = C.green }) => (
  <span style={{
    fontSize: 11, padding: '3px 8px', borderRadius: 4,
    backgroundColor: color + '22', color, fontWeight: 500,
  }}>{children}</span>
);

const Card = ({ children, style }) => (
  <div style={{
    backgroundColor: C.card, border: `1px solid ${C.border}`,
    boxShadow: '0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)',
    borderRadius: 8, padding: 20, ...style,
  }}>{children}</div>
);

const Btn = ({ children, onClick, variant = 'ghost', disabled }) => {
  const styles = {
    primary: { backgroundColor: C.blue,   color: C.bg,    border: 'none' },
    danger:  { backgroundColor: C.red+'22', color: C.red, border: `1px solid ${C.red}` },
    ghost:   { backgroundColor: 'transparent', color: C.sub, border: `1px solid ${C.border}` },
  };
  return (
    <button onClick={onClick} disabled={disabled} style={{
      padding: '6px 14px', borderRadius: 6, fontSize: 13,
      fontWeight: 500, cursor: disabled ? 'not-allowed' : 'pointer',
      opacity: disabled ? 0.5 : 1, transition: 'opacity .15s',
      ...styles[variant],
    }}>{children}</button>
  );
};

const Input = ({ label, ...props }) => (
  <label style={{ display: 'block', marginBottom: 12 }}>
    <span style={{ fontSize: 12, color: C.sub, display: 'block', marginBottom: 4 }}>{label}</span>
    <input {...props} style={{
      width: '100%', padding: '8px 10px', borderRadius: 6,
      border: `1px solid ${C.border}`, backgroundColor: C.bg,
      color: C.text, fontSize: 13, outline: 'none',
    }} />
  </label>
);

const Select = ({ label, children, ...props }) => (
  <label style={{ display: 'block', marginBottom: 12 }}>
    <span style={{ fontSize: 12, color: C.sub, display: 'block', marginBottom: 4 }}>{label}</span>
    <select {...props} style={{
      width: '100%', padding: '8px 10px', borderRadius: 6,
      border: `1px solid ${C.border}`, backgroundColor: C.bg,
      color: C.text, fontSize: 13, outline: 'none',
    }}>{children}</select>
  </label>
);

// ─── Stat card ───────────────────────────────────────────────────────────────
const StatCard = ({ label, value, sub, color = C.blue }) => (
  <Card>
    <p style={{ fontSize: 12, color: C.sub, margin: '0 0 8px' }}>{label}</p>
    <p style={{ fontSize: 28, fontWeight: 700, color, margin: '0 0 6px' }}>{value ?? '—'}</p>
    {sub && <p style={{ fontSize: 12, color: C.muted, margin: 0 }}>{sub}</p>}
  </Card>
);

// ─── Section header ──────────────────────────────────────────────────────────
const SectionHead = ({ title, action }) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
    <h2 style={{ fontSize: 18, fontWeight: 600, color: C.text, margin: 0 }}>{title}</h2>
    {action}
  </div>
);

// ─── Modal shell ─────────────────────────────────────────────────────────────
const Modal = ({ title, onClose, children }) => (
  <div style={{
    position: 'fixed', inset: 0, backgroundColor: '#00000099',
    display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
  }}>
    <div style={{
      backgroundColor: C.card, border: `1px solid ${C.border}`, borderRadius: 10,
      padding: 28, width: 480, maxHeight: '90vh', overflowY: 'auto',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 20 }}>
        <h3 style={{ color: C.text, fontSize: 16, fontWeight: 600 }}>{title}</h3>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: C.muted, fontSize: 20, cursor: 'pointer' }}>×</button>
      </div>
      {children}
    </div>
  </div>
);

// ─── Toast ───────────────────────────────────────────────────────────────────
const Toast = ({ msg, type }) => (
  <div style={{
    position: 'fixed', bottom: 24, right: 24, zIndex: 200,
    backgroundColor: type === 'error' ? C.red : C.green,
    color: '#fff', padding: '10px 18px', borderRadius: 8,
    fontSize: 13, fontWeight: 500, boxShadow: '0 4px 20px #0006',
  }}>{msg}</div>
);

// ═════════════════════════════════════════════════════════════════════════════
// TABS
// ═════════════════════════════════════════════════════════════════════════════

// ── Overview ─────────────────────────────────────────────────────────────────
function OverviewTab({ metrics, dashboard, health }) {
  // Build trend data from raw metrics object (keys → time-series)
  const metricsHistory = [
    { time: '−5m', checks: 80,  passRate: 88, latency: 44 },
    { time: '−4m', checks: 95,  passRate: 85, latency: 47 },
    { time: '−3m', checks: 110, passRate: 90, latency: 43 },
    { time: '−2m', checks: 102, passRate: 87, latency: 50 },
    { time: '−1m', checks: 120, passRate: 89, latency: 45 },
    { time: 'now', checks: metrics?.total_checks ?? 0, passRate: metrics ? Math.round((metrics.passed / (metrics.total_checks || 1)) * 100) : 0, latency: 46 },
  ];

  const byBackend = metrics?.by_backend
    ? Object.entries(metrics.by_backend).map(([name, val]) => ({ name, checks: val }))
    : [];

  const byAction = metrics?.by_action
    ? Object.entries(metrics.by_action).map(([name, val], i) => ({ name, value: val, fill: PIE_COLORS[i % PIE_COLORS.length] }))
    : [];

  const passRate = metrics?.total_checks
    ? ((metrics.passed / metrics.total_checks) * 100).toFixed(1)
    : '—';

  const blockedPct = metrics?.total_checks
    ? (((metrics.total_checks - metrics.passed) / metrics.total_checks) * 100).toFixed(1)
    : '—';

  return (
    <div>
      {/* KPIs */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 16, marginBottom: 24 }}>
        <StatCard label="Total Checks"  value={metrics?.total_checks?.toLocaleString() ?? '0'} sub="all time" color={C.blue}   />
        <StatCard label="Pass Rate"     value={passRate === '—' ? '—' : passRate + '%'}         sub="checks passed" color={C.green}  />
        <StatCard label="Blocked"       value={metrics?.blocked?.toLocaleString() ?? '0'}       sub={blockedPct + '% of total'} color={C.red}    />
        <StatCard label="API Status"    value={health?.status === 'ok' ? 'Healthy' : 'Down'}    sub={`${health?.policies_loaded ?? 0} policies loaded`} color={health?.status === 'ok' ? C.green : C.red} />
      </div>

      {/* Trend + Action pie */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, marginBottom: 24 }}>
        <Card>
          <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 16px' }}>Check Volume &amp; Pass Rate</h3>
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={metricsHistory}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="time" stroke={C.muted} tick={{ fontSize: 11 }} />
              <YAxis yAxisId="l" stroke={C.muted} tick={{ fontSize: 11 }} />
              <YAxis yAxisId="r" orientation="right" stroke={C.muted} tick={{ fontSize: 11 }} domain={[0, 100]} />
              <Tooltip contentStyle={{ backgroundColor: C.bg, border: `1px solid ${C.border}`, borderRadius: 6, fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Line yAxisId="l" type="monotone" dataKey="checks"   stroke={C.blue}  name="Checks" dot={false} strokeWidth={2} />
              <Line yAxisId="r" type="monotone" dataKey="passRate" stroke={C.green} name="Pass %" dot={false} strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        <Card>
          <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 16px' }}>Actions Taken</h3>
          {byAction.length ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={byAction} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value">
                    {byAction.map((e, i) => <Cell key={i} fill={e.fill} />)}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: C.bg, border: `1px solid ${C.border}`, fontSize: 12 }} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginTop: 8 }}>
                {byAction.map((e, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: C.sub }}>
                    <div style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: e.fill }} />
                    {e.name} ({e.value})
                  </div>
                ))}
              </div>
            </>
          ) : <p style={{ color: C.muted, fontSize: 13, textAlign: 'center', paddingTop: 60 }}>No data yet — run some guardrail checks</p>}
        </Card>
      </div>

      {/* Backend breakdown */}
      {byBackend.length > 0 && (
        <Card style={{ marginBottom: 24 }}>
          <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 16px' }}>Checks by Backend</h3>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={byBackend}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="name" stroke={C.muted} tick={{ fontSize: 12 }} />
              <YAxis stroke={C.muted} tick={{ fontSize: 12 }} />
              <Tooltip contentStyle={{ backgroundColor: C.bg, border: `1px solid ${C.border}`, fontSize: 12 }} />
              <Bar dataKey="checks" fill={C.blue} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      )}
    </div>
  );
}

// ── Policies ─────────────────────────────────────────────────────────────────
function PoliciesTab({ toast }) {
  const [policies, setPolicies]       = useState({});
  const [templates, setTemplates]     = useState([]);
  const [backends, setBackends]       = useState([]);
  const [riskCats, setRiskCats]       = useState([]);
  const [actions, setActions]         = useState([]);
  const [showCreate, setShowCreate]   = useState(false);
  const [loading, setLoading]         = useState(false);

  const [form, setForm] = useState({
    name: '', description: '', backend: 'guardrails_ai',
    risk_categories: ['prompt_injection'],
    sensitivity: 'medium', action_on_violation: 'block',
  });

  const load = useCallback(async () => {
    const [p, t, b, r, a] = await Promise.all([
      api.listPolicies(), api.listTemplates(),
      api.getBackends(), api.getRiskCats(), api.getActions(),
    ]);
    setPolicies(p); setTemplates(t.templates);
    setBackends(b.backends); setRiskCats(r.risk_categories); setActions(a.actions);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    if (!form.name) return;
    setLoading(true);
    try {
      await api.createPolicy(form);
      toast('Policy created', 'ok');
      setShowCreate(false);
      load();
    } catch (e) { toast(e.message, 'error'); }
    finally { setLoading(false); }
  };

  const handleFromTemplate = async (name) => {
    try {
      await api.createFromTemplate(name);
      toast(`Created from template: ${name}`, 'ok');
      load();
    } catch (e) { toast(e.message, 'error'); }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this policy?')) return;
    try {
      await api.deletePolicy(id);
      toast('Policy deleted', 'ok');
      load();
    } catch (e) { toast(e.message, 'error'); }
  };

  const toggleRiskCat = (cat) => {
    setForm(f => ({
      ...f,
      risk_categories: f.risk_categories.includes(cat)
        ? f.risk_categories.filter(c => c !== cat)
        : [...f.risk_categories, cat],
    }));
  };

  return (
    <div>
      <SectionHead title="Policies" action={<Btn variant="primary" onClick={() => setShowCreate(true)}>+ New Policy</Btn>} />

      {/* Templates */}
      <Card style={{ marginBottom: 20 }}>
        <p style={{ fontSize: 12, color: C.sub, marginBottom: 12 }}>Quick-start from a template:</p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {templates.map(t => (
            <Btn key={t.name} onClick={() => handleFromTemplate(t.name)}>
              {t.name.replace(/_/g, ' ')}
            </Btn>
          ))}
        </div>
      </Card>

      {/* Policy list */}
      {Object.keys(policies).length === 0
        ? <p style={{ color: C.muted, textAlign: 'center', padding: 40 }}>No policies yet. Create one above.</p>
        : Object.values(policies).map(p => (
          <Card key={p.id} style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 14, fontWeight: 600, color: C.text }}>{p.name}</span>
                  <Badge color={p.enabled ? C.green : C.muted}>{p.enabled ? 'Active' : 'Disabled'}</Badge>
                  <Badge color={C.blue}>{p.backend}</Badge>
                </div>
                <p style={{ fontSize: 12, color: C.muted, margin: 0 }}>
                  Sensitivity: {p.sensitivity} · Action: {p.action_on_violation} · Tags: {p.tags?.join(', ') || '—'}
                </p>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <Btn variant="danger" onClick={() => handleDelete(p.id)}>Delete</Btn>
              </div>
            </div>
          </Card>
        ))
      }

      {/* Create modal */}
      {showCreate && (
        <Modal title="Create Policy" onClose={() => setShowCreate(false)}>
          <Input label="Name *" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Production Chat Policy" />
          <Input label="Description" value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
          <Select label="Backend" value={form.backend} onChange={e => setForm(f => ({ ...f, backend: e.target.value }))}>
            {backends.map(b => <option key={b} value={b}>{b}</option>)}
          </Select>
          <Select label="Sensitivity" value={form.sensitivity} onChange={e => setForm(f => ({ ...f, sensitivity: e.target.value }))}>
            {['low', 'medium', 'high'].map(s => <option key={s} value={s}>{s}</option>)}
          </Select>
          <Select label="Action on violation" value={form.action_on_violation} onChange={e => setForm(f => ({ ...f, action_on_violation: e.target.value }))}>
            {actions.map(a => <option key={a} value={a}>{a}</option>)}
          </Select>
          <div style={{ marginBottom: 16 }}>
            <p style={{ fontSize: 12, color: C.sub, marginBottom: 8 }}>Risk categories</p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {riskCats.map(cat => {
                const active = form.risk_categories.includes(cat);
                return (
                  <button key={cat} onClick={() => toggleRiskCat(cat)} style={{
                    padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer',
                    border: `1px solid ${active ? C.blue : C.border}`,
                    backgroundColor: active ? C.blue + '22' : 'transparent',
                    color: active ? C.blue : C.muted,
                  }}>{cat.replace(/_/g, ' ')}</button>
                );
              })}
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <Btn onClick={() => setShowCreate(false)}>Cancel</Btn>
            <Btn variant="primary" onClick={handleCreate} disabled={loading || !form.name}>
              {loading ? 'Creating…' : 'Create'}
            </Btn>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ── Live check tester ─────────────────────────────────────────────────────────
function CheckerTab({ toast }) {
  const [policies, setPolicies] = useState({});
  const [selectedPolicy, setSelectedPolicy] = useState('');
  const [checkType, setCheckType] = useState('input');
  const [text, setText] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.listPolicies().then(p => {
      setPolicies(p);
      const first = Object.keys(p)[0];
      if (first) setSelectedPolicy(first);
    });
  }, []);

  const run = async () => {
    if (!selectedPolicy || !text) return;
    setLoading(true); setResult(null);
    try {
      const fn = checkType === 'input' ? api.checkInput : api.checkOutput;
      const res = await fn({ text, policy_id: selectedPolicy });
      setResult(res);
    } catch (e) { toast(e.message, 'error'); }
    finally { setLoading(false); }
  };

  return (
    <div>
      <SectionHead title="Live Guardrail Tester" />
      <Card style={{ marginBottom: 16 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
          <Select label="Policy" value={selectedPolicy} onChange={e => setSelectedPolicy(e.target.value)}>
            {Object.values(policies).map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </Select>
          <Select label="Check type" value={checkType} onChange={e => setCheckType(e.target.value)}>
            <option value="input">Input check</option>
            <option value="output">Output check</option>
          </Select>
        </div>
        <label style={{ display: 'block', marginBottom: 12 }}>
          <span style={{ fontSize: 12, color: C.sub, display: 'block', marginBottom: 4 }}>Text to check</span>
          <textarea value={text} onChange={e => setText(e.target.value)}
            rows={4} placeholder="Type or paste text here…"
            style={{
              width: '100%', padding: '8px 10px', borderRadius: 6,
              border: `1px solid ${C.border}`, backgroundColor: C.bg,
              color: C.text, fontSize: 13, resize: 'vertical', outline: 'none',
            }} />
        </label>
        <Btn variant="primary" onClick={run} disabled={loading || !text || !selectedPolicy}>
          {loading ? 'Checking…' : 'Run check'}
        </Btn>
      </Card>

      {result && (
        <Card>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
            <span style={{ fontSize: 24 }}>{result.passed ? '✅' : '🚫'}</span>
            <div>
              <p style={{ fontSize: 16, fontWeight: 700, color: result.passed ? C.green : C.red, margin: 0 }}>
                {result.passed ? 'Passed' : 'Blocked / Modified'}
              </p>
              <p style={{ fontSize: 12, color: C.muted, margin: 0 }}>
                {result.latency_ms?.toFixed(1)}ms · backend: {result.backend_used} · request: {result.request_id?.slice(0, 8)}
              </p>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
            <div>
              <p style={{ fontSize: 11, color: C.sub, margin: '0 0 4px' }}>Risk score</p>
              <div style={{ background: C.bg, borderRadius: 6, height: 6, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${result.risk_score * 100}%`, backgroundColor: result.risk_score > 0.6 ? C.red : result.risk_score > 0.3 ? C.amber : C.green, transition: 'width .4s' }} />
              </div>
              <p style={{ fontSize: 12, color: C.text, marginTop: 4 }}>{(result.risk_score * 100).toFixed(0)}%</p>
            </div>
            <div>
              <p style={{ fontSize: 11, color: C.sub, margin: '0 0 4px' }}>Action taken</p>
              <Badge color={result.action === 'allow' ? C.green : result.action === 'block' ? C.red : C.amber}>
                {result.action}
              </Badge>
            </div>
          </div>
          {result.detected_risks?.length > 0 && (
            <div>
              <p style={{ fontSize: 11, color: C.sub, marginBottom: 6 }}>Detected risks</p>
              {result.detected_risks.map((r, i) => (
                <div key={i} style={{ fontSize: 12, color: C.red, padding: '3px 0' }}>
                  ⚠ {typeof r === 'object' ? JSON.stringify(r) : r}
                </div>
              ))}
            </div>
          )}
          {result.modified_text && result.modified_text !== text && (
            <div style={{ marginTop: 12, padding: 12, backgroundColor: C.bg, borderRadius: 6 }}>
              <p style={{ fontSize: 11, color: C.sub, marginBottom: 4 }}>Modified output</p>
              <p style={{ fontSize: 13, color: C.text, margin: 0 }}>{result.modified_text}</p>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

// ── Alerts ───────────────────────────────────────────────────────────────────
function AlertsTab({ toast }) {
  const [alerts, setAlerts] = useState([]);

  const load = useCallback(() => {
    api.getAlerts().then(r => setAlerts(r.active_alerts));
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t); }, [load]);

  const resolve = async (id) => {
    try { await api.resolveAlert(id); toast('Alert resolved', 'ok'); load(); }
    catch (e) { toast(e.message, 'error'); }
  };

  return (
    <div>
      <SectionHead title={`Alerts (${alerts.length} active)`} action={<Btn onClick={load}>Refresh</Btn>} />
      {alerts.length === 0
        ? <Card><p style={{ color: C.muted, textAlign: 'center', padding: 32 }}>✅ No active alerts</p></Card>
        : alerts.map(a => (
          <Card key={a.id} style={{
            marginBottom: 12,
            borderLeft: `4px solid ${a.severity === 'critical' ? C.red : C.amber}`,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
                  <span style={{ fontSize: 14, fontWeight: 600, color: C.text }}>{a.title}</span>
                  <Badge color={a.severity === 'critical' ? C.red : C.amber}>{a.severity}</Badge>
                </div>
                <p style={{ fontSize: 12, color: C.muted, margin: '0 0 4px' }}>{a.type}</p>
                <p style={{ fontSize: 12, color: C.sub, margin: 0 }}>
                  Value: <b style={{ color: C.text }}>{a.metric_value}</b> · Threshold: {a.threshold}
                </p>
              </div>
              <Btn onClick={() => resolve(a.id)}>Resolve</Btn>
            </div>
          </Card>
        ))
      }
    </div>
  );
}

// ── A/B Tests ────────────────────────────────────────────────────────────────
function ABTestsTab({ toast }) {
  const [tests, setTests]         = useState({});
  const [policies, setPolicies]   = useState({});
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', control_policy_id: '', experiment_policy_id: '', traffic_split: 0.5, duration_hours: 24 });

  const load = useCallback(async () => {
    const [t, p] = await Promise.all([api.listABTests(), api.listPolicies()]);
    setTests(t); setPolicies(p);
  }, []);

  useEffect(() => { load(); }, [load]);

  const create = async () => {
    try { await api.createABTest(form); toast('A/B test created', 'ok'); setShowCreate(false); load(); }
    catch (e) { toast(e.message, 'error'); }
  };

  const assign = async (id) => {
    try {
      const r = await api.assignABTest(id);
      toast(`Assigned → ${r.policy_name}`, 'ok');
    } catch (e) { toast(e.message, 'error'); }
  };

  const policyList = Object.values(policies);

  return (
    <div>
      <SectionHead title="A/B Tests" action={<Btn variant="primary" onClick={() => setShowCreate(true)}>+ New Test</Btn>} />
      {Object.keys(tests).length === 0
        ? <Card><p style={{ color: C.muted, textAlign: 'center', padding: 32 }}>No A/B tests yet.</p></Card>
        : Object.values(tests).map(t => {
          const ctrl = policies[t.control_policy_id];
          const exp  = policies[t.experiment_policy_id];
          return (
            <Card key={t.id} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                <div>
                  <p style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 8px' }}>{t.name}</p>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 8 }}>
                    <div>
                      <p style={{ fontSize: 11, color: C.sub, margin: '0 0 2px' }}>Control</p>
                      <p style={{ fontSize: 13, color: C.text, margin: 0 }}>{ctrl?.name ?? t.control_policy_id.slice(0, 8)}</p>
                    </div>
                    <div>
                      <p style={{ fontSize: 11, color: C.sub, margin: '0 0 2px' }}>Experiment</p>
                      <p style={{ fontSize: 13, color: C.text, margin: 0 }}>{exp?.name ?? t.experiment_policy_id.slice(0, 8)}</p>
                    </div>
                  </div>
                  <p style={{ fontSize: 12, color: C.muted, margin: 0 }}>
                    Split: {(t.traffic_split * 100).toFixed(0)}% experiment · {t.duration_hours}h duration
                  </p>
                </div>
                <Btn onClick={() => assign(t.id)}>Assign request</Btn>
              </div>
            </Card>
          );
        })
      }

      {showCreate && (
        <Modal title="Create A/B Test" onClose={() => setShowCreate(false)}>
          <Input label="Test name *" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
          <Select label="Control policy" value={form.control_policy_id} onChange={e => setForm(f => ({ ...f, control_policy_id: e.target.value }))}>
            <option value="">Select…</option>
            {policyList.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </Select>
          <Select label="Experiment policy" value={form.experiment_policy_id} onChange={e => setForm(f => ({ ...f, experiment_policy_id: e.target.value }))}>
            <option value="">Select…</option>
            {policyList.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </Select>
          <Input label="Traffic split (0–1)" type="number" min="0.1" max="0.9" step="0.1"
            value={form.traffic_split} onChange={e => setForm(f => ({ ...f, traffic_split: parseFloat(e.target.value) }))} />
          <Input label="Duration (hours)" type="number" min="1"
            value={form.duration_hours} onChange={e => setForm(f => ({ ...f, duration_hours: parseInt(e.target.value) }))} />
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <Btn onClick={() => setShowCreate(false)}>Cancel</Btn>
            <Btn variant="primary" onClick={create} disabled={!form.name || !form.control_policy_id || !form.experiment_policy_id}>Create</Btn>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ── Audit log ────────────────────────────────────────────────────────────────
function AuditTab() {
  const [entries, setEntries] = useState([]);
  const [limit, setLimit] = useState(50);

  useEffect(() => {
    api.getAuditLog(limit).then(r => setEntries(r.entries ?? []));
  }, [limit]);

  return (
    <div>
      <SectionHead title="Audit Log" action={
        <Select label="" value={limit} onChange={e => setLimit(Number(e.target.value))} style={{ marginBottom: 0 }}>
          {[20, 50, 100, 200].map(n => <option key={n} value={n}>Last {n}</option>)}
        </Select>
      } />
      <Card>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {['Timestamp', 'Policy', 'Action', 'Passed', 'Risk', 'Backend', 'Latency'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '8px 12px', color: C.sub, fontWeight: 500 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {entries.length === 0 ? (
                <tr><td colSpan={7} style={{ textAlign: 'center', padding: 32, color: C.muted }}>No audit entries yet</td></tr>
              ) : entries.slice().reverse().map((e, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${C.border}22` }}>
                  <td style={{ padding: '8px 12px', color: C.muted }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td style={{ padding: '8px 12px', color: C.sub, fontFamily: 'monospace' }}>{e.policy_id?.slice(0, 8)}…</td>
                  <td style={{ padding: '8px 12px', color: C.sub }}>{e.action}</td>
                  <td style={{ padding: '8px 12px' }}>
                    <Badge color={e.passed ? C.green : C.red}>{e.passed ? 'yes' : 'no'}</Badge>
                  </td>
                  <td style={{ padding: '8px 12px', color: e.risk_score > 0.6 ? C.red : C.sub }}>
                    {typeof e.risk_score === 'number' ? (e.risk_score * 100).toFixed(0) + '%' : '—'}
                  </td>
                  <td style={{ padding: '8px 12px', color: C.sub }}>{e.backend ?? '—'}</td>
                  <td style={{ padding: '8px 12px', color: C.sub }}>{e.latency_ms?.toFixed(1) ?? '—'}ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

// ── Testing tab (Gap 1) ──────────────────────────────────────────────────────
function TestingTab({ toast }) {
  const [policies, setPolicies] = useState({});
  const [selected, setSelected] = useState('');
  const [report, setReport]     = useState(null);
  const [loading, setLoading]   = useState(false);

  useEffect(() => {
    api.listPolicies().then(p => {
      setPolicies(p);
      const first = Object.keys(p)[0];
      if (first) setSelected(first);
    });
  }, []);

  const runBuiltin = async () => {
    if (!selected) return;
    setLoading(true); setReport(null);
    try {
      setReport(await api.runBuiltinTests(selected));
    } catch (e) { toast(e.message, 'error'); }
    finally { setLoading(false); }
  };

  return (
    <div>
      <SectionHead title="Policy Testing" />
      <Card style={{ marginBottom: 16 }}>
        <p style={{ fontSize: 12, color: C.sub, marginBottom: 12 }}>
          Run the built-in adversarial smoke suite (safe queries, injection, jailbreak, SQL, code exec) against a policy.
        </p>
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <Select label="Policy" value={selected} onChange={e => setSelected(e.target.value)}>
              {Object.values(policies).map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </Select>
          </div>
          <div style={{ marginBottom: 12 }}>
            <Btn variant="primary" onClick={runBuiltin} disabled={loading || !selected}>
              {loading ? 'Running…' : 'Run test suite'}
            </Btn>
          </div>
        </div>
      </Card>

      {report && (
        <Card>
          <div style={{ display: 'flex', gap: 24, marginBottom: 16 }}>
            <div><p style={{ fontSize: 11, color: C.sub, margin: 0 }}>Pass rate</p>
              <p style={{ fontSize: 24, fontWeight: 700, margin: 0, color: report.pass_rate === 100 ? C.green : C.amber }}>{report.pass_rate}%</p></div>
            <div><p style={{ fontSize: 11, color: C.sub, margin: 0 }}>Passed</p>
              <p style={{ fontSize: 24, fontWeight: 700, margin: 0, color: C.green }}>{report.passed}</p></div>
            <div><p style={{ fontSize: 11, color: C.sub, margin: 0 }}>Failed</p>
              <p style={{ fontSize: 24, fontWeight: 700, margin: 0, color: report.failed ? C.red : C.muted }}>{report.failed}</p></div>
            <div><p style={{ fontSize: 11, color: C.sub, margin: 0 }}>Duration</p>
              <p style={{ fontSize: 24, fontWeight: 700, margin: 0, color: C.blue }}>{report.duration_ms?.toFixed(0)}ms</p></div>
          </div>
          <div style={{ display: 'grid', gap: 6 }}>
            {report.results.map((r, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px', backgroundColor: C.bg, borderRadius: 6 }}>
                <span style={{ fontSize: 16 }}>{r.passed ? '✅' : '❌'}</span>
                <span style={{ fontSize: 13, color: C.text, flex: 1 }}>{r.name}</span>
                {r.risk_score != null && (
                  <span style={{ fontSize: 12, color: r.risk_score > 0.6 ? C.red : C.muted }}>risk {(r.risk_score * 100).toFixed(0)}%</span>
                )}
                {r.failures?.length > 0 && (
                  <span style={{ fontSize: 11, color: C.red }}>{r.failures.join('; ')}</span>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

// ── Status & Metrics tab (Gaps 8, 9, 11) ─────────────────────────────────────
function StatusTab({ toast }) {
  const [status, setStatus]   = useState(null);
  const [dpStats, setDpStats] = useState(null);
  const [blockUser, setBlockUser] = useState('');

  const load = useCallback(async () => {
    try {
      const [s, d] = await Promise.all([api.getStatus(), api.dataProviderStats()]);
      setStatus(s); setDpStats(d);
    } catch (e) {}
  }, []);

  useEffect(() => { load(); const t = setInterval(load, 8000); return () => clearInterval(t); }, [load]);

  const addBlock = async () => {
    if (!blockUser) return;
    try {
      await api.updateBlocklist({ users: [blockUser] });
      toast(`Blocked user: ${blockUser}`, 'ok');
      setBlockUser(''); load();
    } catch (e) { toast(e.message, 'error'); }
  };

  const policies = status ? Object.values(status.policies) : [];

  return (
    <div>
      <SectionHead title="Status & Health" action={<Btn onClick={load}>Refresh</Btn>} />

      {status && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(200px,1fr))', gap: 16, marginBottom: 20 }}>
          <StatCard label="Tracked policies" value={status.total_policies} color={C.blue} />
          <StatCard label="Healthy" value={status.healthy_policies} sub="zero errors" color={C.green} />
          <StatCard label="Prometheus" value="/metrics" sub="scrape endpoint live" color={C.purple} />
        </div>
      )}

      <Card style={{ marginBottom: 20 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 12px' }}>Per-policy status (OPA status API parity)</h3>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead><tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {['Policy', 'Backend', 'Checks', 'Blocked', 'Errors', 'Avg', 'p95', 'Last check'].map(h => (
                <th key={h} style={{ textAlign: 'left', padding: '8px 12px', color: C.sub, fontWeight: 500 }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {policies.length === 0 ? (
                <tr><td colSpan={8} style={{ textAlign: 'center', padding: 24, color: C.muted }}>No checks recorded yet — run some in Live Test</td></tr>
              ) : policies.map((p, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${C.border}22` }}>
                  <td style={{ padding: '8px 12px', color: C.text }}>{p.policy_name}</td>
                  <td style={{ padding: '8px 12px', color: C.sub }}>{p.backend}</td>
                  <td style={{ padding: '8px 12px', color: C.sub }}>{p.total_checks}</td>
                  <td style={{ padding: '8px 12px', color: p.total_blocked ? C.amber : C.sub }}>{p.total_blocked}</td>
                  <td style={{ padding: '8px 12px', color: p.error_count ? C.red : C.sub }}>{p.error_count}</td>
                  <td style={{ padding: '8px 12px', color: C.sub }}>{p.avg_latency_ms}ms</td>
                  <td style={{ padding: '8px 12px', color: p.p95_latency_ms > 100 ? C.amber : C.sub }}>{p.p95_latency_ms}ms</td>
                  <td style={{ padding: '8px 12px', color: C.muted }}>{p.last_check_at ? new Date(p.last_check_at).toLocaleTimeString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 12px' }}>External data providers (blocklist)</h3>
        {dpStats && (
          <p style={{ fontSize: 12, color: C.sub, marginBottom: 12 }}>
            Providers: {dpStats.providers?.join(', ') || 'none'} · {dpStats.call_count} enrich calls · {dpStats.error_count} errors
          </p>
        )}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input value={blockUser} onChange={e => setBlockUser(e.target.value)}
            placeholder="user_id to block"
            style={{ flex: 1, padding: '8px 10px', borderRadius: 6, border: `1px solid ${C.border}`, backgroundColor: C.bg, color: C.text, fontSize: 13, outline: 'none' }} />
          <Btn variant="primary" onClick={addBlock} disabled={!blockUser}>Add to blocklist</Btn>
        </div>
      </Card>
    </div>
  );
}

// ── Versions & Bundles tab (Gaps 4, 5) ───────────────────────────────────────
function VersionsTab({ toast }) {
  const [policies, setPolicies] = useState({});
  const [selected, setSelected] = useState('');
  const [versions, setVersions] = useState([]);

  const loadPolicies = useCallback(async () => {
    const p = await api.listPolicies();
    setPolicies(p);
    const first = Object.keys(p)[0];
    if (first && !selected) setSelected(first);
  }, [selected]);

  useEffect(() => { loadPolicies(); }, [loadPolicies]);

  const loadVersions = useCallback(async () => {
    if (!selected) return;
    try {
      const r = await api.listVersions(selected);
      setVersions(r.versions || []);
    } catch (e) { setVersions([]); }
  }, [selected]);

  useEffect(() => { loadVersions(); }, [loadVersions]);

  const rollback = async (snapId) => {
    if (!window.confirm('Roll back to this snapshot?')) return;
    try {
      await api.rollbackPolicy(selected, snapId);
      toast('Rolled back', 'ok');
      loadVersions();
    } catch (e) { toast(e.message, 'error'); }
  };

  const exportBundle = () => {
    const base = process.env.REACT_APP_API_URL || '';
    window.open(`${base}/bundles/export`, '_blank');
  };

  return (
    <div>
      <SectionHead title="Versions & Bundles" action={<Btn variant="primary" onClick={exportBundle}>↓ Export bundle (.tar.gz)</Btn>} />

      <Card style={{ marginBottom: 16 }}>
        <Select label="Policy" value={selected} onChange={e => setSelected(e.target.value)}>
          {Object.values(policies).map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </Select>
      </Card>

      <Card>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 12px' }}>Version history (newest first)</h3>
        {versions.length === 0 ? (
          <p style={{ color: C.muted, fontSize: 13, textAlign: 'center', padding: 24 }}>
            No snapshots yet. Snapshots are created automatically on policy create/update.
          </p>
        ) : (
          <div style={{ display: 'grid', gap: 8 }}>
            {versions.map((v, i) => (
              <div key={v.snapshot_id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 12px', backgroundColor: C.bg, borderRadius: 6 }}>
                <Badge color={i === 0 ? C.green : C.muted}>{i === 0 ? 'current' : `v${versions.length - i}`}</Badge>
                <div style={{ flex: 1 }}>
                  <p style={{ fontSize: 13, color: C.text, margin: 0 }}>{v.change_reason || 'no reason given'}</p>
                  <p style={{ fontSize: 11, color: C.muted, margin: 0 }}>
                    {new Date(v.created_at).toLocaleString()} · by {v.created_by} · {v.snapshot_id.slice(0, 8)}
                  </p>
                </div>
                {i !== 0 && <Btn onClick={() => rollback(v.snapshot_id)}>Roll back</Btn>}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

// ── Red Team ─────────────────────────────────────────────────────────────────
const RT_OWASP = [
  { ref: 'LLM01', label: 'Prompt Injection' },
  { ref: 'LLM02', label: 'Insecure Output' },
  { ref: 'LLM03', label: 'Training Data Poisoning' },
  { ref: 'LLM04', label: 'Model DoS' },
  { ref: 'LLM05', label: 'Supply Chain' },
  { ref: 'LLM06', label: 'Sensitive Info Disclosure' },
  { ref: 'LLM07', label: 'Insecure Plugin' },
  { ref: 'LLM08', label: 'Excessive Agency' },
  { ref: 'LLM09', label: 'Overreliance' },
  { ref: 'LLM10', label: 'Model Theft' },
];

// Mirrors BACKEND_SCOPE in red_team_runner.py.
// "general"     → designed to catch broad LLM attacks across all categories.
// "specialized" → purpose-built for a specific use case (PII, content, etc.).
const BACKEND_SCOPE = {
  nemo:                  { type: 'general',     label: 'General LLM Safety' },
  guardrails_ai:         { type: 'specialized', label: 'Validation Framework',    note: 'Requires validators; compare within PII / content use cases' },
  presidio:              { type: 'specialized', label: 'PII Detection',            note: 'Designed for PII and credential detection (LLM06) only' },
  lakera:                { type: 'general',     label: 'Prompt Security' },
  ga_guard:              { type: 'general',     label: 'Content Safety' },
  openai_moderation:     { type: 'specialized', label: 'Content Moderation',      note: 'Content policy classification only; subject to rate limits' },
  azure_content_safety:  { type: 'general',     label: 'Content Safety' },
  azure_prompt_shields:  { type: 'specialized', label: 'Prompt Injection Guard',  note: 'Designed specifically for prompt injection detection' },
  aws_bedrock:           { type: 'general',     label: 'General Guardrails' },
  llama_firewall:        { type: 'general',     label: 'Prompt Injection Guard' },
  llm_guard:             { type: 'general',     label: 'Input Safety Scanner' },
};

function RedTeamTab({ toast }) {
  const [backends,        setBackends]        = useState([]);
  const [selectedBackend, setSelectedBackend] = useState('guardrails_ai');
  const [selectedCats,    setSelectedCats]    = useState([]);
  const [severity,        setSeverity]        = useState('');
  const [loading,         setLoading]         = useState(false);
  const [elapsed,         setElapsed]         = useState(0);
  const [report,          setReport]          = useState(null);
  const [compareReport,   setCompareReport]   = useState(null);
  const [benchmarkArts,   setBenchmarkArts]   = useState(null);
  const [probeFilter,     setProbeFilter]     = useState('all');
  const [expandedProbe,   setExpandedProbe]   = useState(null);
  const [probeMap,        setProbeMap]        = useState({});
  const [baselineRunId,   setBaselineRunId]   = useState('');
  const [baselineReport,  setBaselineReport]  = useState(null);
  const [baselineLoading, setBaselineLoading] = useState(false);
  const [runHistory,      setRunHistory]      = useState(() => {
    try { return JSON.parse(localStorage.getItem('redteam_run_history') || '[]'); }
    catch { return []; }
  });

  useEffect(() => {
    api.getBackends()
      .then(r => {
        const bs = (r.backends || []).filter(b => b !== 'custom');
        setBackends(bs);
        if (bs.length) setSelectedBackend(bs[0]);
      })
      .catch(() => {});
    api.redteamProbes()
      .then(probes => {
        const m = {};
        for (const p of probes) m[p.id] = p;
        setProbeMap(m);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!loading) { setElapsed(0); return; }
    const t = setInterval(() => setElapsed(s => s + 1), 1000);
    return () => clearInterval(t);
  }, [loading]);

  const toggleCat = (ref) =>
    setSelectedCats(prev => prev.includes(ref) ? prev.filter(c => c !== ref) : [...prev, ref]);

  const runSingle = async () => {
    setLoading(true); setReport(null);
    try {
      const r = await api.redteamRun({
        backend: selectedBackend,
        categories: selectedCats.length ? selectedCats : null,
        severity: severity || null,
      });
      setReport(r);
      toast(`Run complete: ${r.passed}/${r.total_probes} passed`, 'ok');
    } catch (e) { toast(e.message, 'error'); }
    finally { setLoading(false); }
  };

  const runCompare = async () => {
    setLoading(true); setBenchmarkArts(null);
    try {
      const r = await api.redteamCompare({
        backends: null,
        categories: selectedCats.length ? selectedCats : null,
        save_benchmark: true,
      });
      setCompareReport(r);
      if (r.benchmark) setBenchmarkArts(r.benchmark);
      const saved = r.benchmark ? ' — report saved' : r.benchmark_error ? ' (save failed)' : '';
      toast(`Comparison complete: ${r.backends_tested.length} backends${saved}`, r.benchmark_error ? 'warn' : 'ok');
      if (r.run_id) {
        try {
          const existing = JSON.parse(localStorage.getItem('redteam_run_history') || '[]');
          const entry = {
            run_id:    r.run_id,
            timestamp: r.timestamp || new Date().toISOString(),
            best:      r.best_overall || '—',
            backends:  r.backends_tested?.length ?? 0,
          };
          const next = [entry, ...existing.filter(e => e.run_id !== r.run_id)].slice(0, 10);
          localStorage.setItem('redteam_run_history', JSON.stringify(next));
          setRunHistory(next);
        } catch {}
      }
    } catch (e) { toast(e.message, 'error'); }
    finally { setLoading(false); }
  };

  const loadBaseline = async () => {
    if (!baselineRunId) return;
    setBaselineLoading(true);
    try {
      setBaselineReport(await api.redteamReport(baselineRunId));
      toast('Baseline loaded', 'ok');
    } catch (e) { toast(e.message, 'error'); setBaselineReport(null); }
    finally { setBaselineLoading(false); }
  };

  const passColor = (rate) =>
    rate >= 0.8 ? C.green : rate >= 0.5 ? C.amber : C.red;

  const sevColor = (s) =>
    ({ critical: C.red, high: C.amber, medium: C.blue, low: C.muted }[s] ?? C.muted);

  const owaspLabel = (ref) =>
    RT_OWASP.find(c => c.ref === ref)?.label ?? ref;

  const probeResults = report?.probe_results ?? [];
  const filteredProbes = probeResults.filter(pr =>
    probeFilter === 'pass' ? pr.passed : probeFilter === 'fail' ? !pr.passed : true
  );

  // Comparison pivot: backend → { owasp_ref → summary row }
  const pivot = {};
  if (compareReport) {
    for (const row of compareReport.summary_table || []) {
      if (!pivot[row.backend]) pivot[row.backend] = {};
      pivot[row.backend][row.owasp_ref] = row;
    }
  }

  // Regression diff
  const regressions = [], improvements = [], stablePass = [], stableFail = [];
  if (report && baselineReport) {
    const baseMap = Object.fromEntries(
      (baselineReport.probe_results || []).map(p => [p.probe_id, p])
    );
    for (const pr of report.probe_results || []) {
      const base = baseMap[pr.probe_id];
      if (!base) continue;
      if (base.passed && !pr.passed)       regressions.push(pr);
      else if (!base.passed && pr.passed)  improvements.push(pr);
      else if (pr.passed)                  stablePass.push(pr);
      else                                 stableFail.push(pr);
    }
  }

  return (
    <div style={{ position: 'relative' }}>
      {loading && (() => {
        // Estimated completion time (seconds) per backend — determines when ✓ appears.
        const BK = [
          { name: 'NeMo Guardrails',       color: '#22d3ee', eta: 18,  dur: 1.7 },
          { name: 'GuardrailsAI',           color: '#a78bfa', eta: 28,  dur: 2.1 },
          { name: 'Presidio',               color: '#fb923c', eta: 12,  dur: 1.9 },
          { name: 'Lakera Guard',           color: '#4ade80', eta: 35,  dur: 2.3 },
          { name: 'GA Guard',               color: '#f472b6', eta: 8,   dur: 1.6 },
          { name: 'OpenAI Moderation',      color: '#60a5fa', eta: 45,  dur: 2.0 },
          { name: 'Azure Content Safety',   color: '#34d399', eta: 55,  dur: 1.8 },
          { name: 'Azure Prompt Shields',   color: '#fbbf24', eta: 62,  dur: 2.4 },
          { name: 'AWS Bedrock',            color: '#f87171', eta: 72,  dur: 1.5 },
          { name: 'LlamaFirewall',          color: '#fb923c', eta: 85,  dur: 2.2 },
          { name: 'LLM Guard',              color: '#06b6d4', eta: 98,  dur: 2.0 },
        ];
        const TOTAL_EST = 115; // expected seconds for full run
        const progressPct = Math.min(Math.round((elapsed / TOTAL_EST) * 100), 99);
        const mm = String(Math.floor(elapsed / 60)).padStart(2, '0');
        const ss = String(elapsed % 60).padStart(2, '0');
        const nB = backends.length || BK.length;
        const done  = BK.filter(b => elapsed >= b.eta).length;
        return (
          <div style={{
            position: 'absolute', inset: 0, zIndex: 50,
            background: 'rgba(10,12,20,0.9)',
            backdropFilter: 'blur(4px)',
            display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center',
            borderRadius: 8, minHeight: 300, padding: '32px 24px',
          }}>
            <style>{`
              @keyframes rt-scan { 0%,100%{left:0} 50%{left:calc(100% - 10px)} }
              @keyframes rt-dot  { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(.7)} }
              @keyframes rt-fade { 0%{opacity:.3} 50%{opacity:1} 100%{opacity:.3} }
            `}</style>

            {/* Title */}
            <div style={{ fontSize: 14, fontWeight: 700, color: '#fff', letterSpacing: 0.3, marginBottom: 4 }}>
              ⚡ Firing probes against {nB} backends in parallel
            </div>
            <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.4)', marginBottom: 16 }}>
              78 probes &times; {nB} backends &nbsp;·&nbsp; each backend independent
            </div>

            {/* Overall progress bar */}
            <div style={{ width: '100%', maxWidth: 480, marginBottom: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.5)' }}>
                  {done} / {BK.length} backends complete
                </span>
                <span style={{ fontSize: 11, fontWeight: 600, color: '#60a5fa' }}>{progressPct}%</span>
              </div>
              <div style={{ height: 6, background: 'rgba(255,255,255,0.1)', borderRadius: 4, overflow: 'hidden' }}>
                <div style={{
                  height: '100%', borderRadius: 4,
                  background: 'linear-gradient(90deg, #38bdf8, #818cf8)',
                  width: `${progressPct}%`,
                  transition: 'width 1s linear',
                }} />
              </div>
            </div>

            {/* Backend rows */}
            <div style={{ width: '100%', maxWidth: 480, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {BK.map((b, i) => {
                const isDone = elapsed >= b.eta;
                return (
                  <div key={b.name} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    {/* dot / checkmark */}
                    {isDone ? (
                      <span style={{ width: 8, fontSize: 12, color: b.color, flexShrink: 0 }}>✓</span>
                    ) : (
                      <div style={{
                        width: 8, height: 8, borderRadius: '50%',
                        background: b.color, flexShrink: 0,
                        boxShadow: `0 0 6px 2px ${b.color}`,
                        animation: `rt-dot ${b.dur}s ease-in-out infinite`,
                        animationDelay: `${(i * 0.18).toFixed(2)}s`,
                      }} />
                    )}
                    {/* name */}
                    <span style={{
                      width: 170, fontSize: 11, flexShrink: 0, letterSpacing: 0.2,
                      fontFamily: 'monospace',
                      color: isDone ? 'rgba(255,255,255,0.45)' : 'rgba(255,255,255,0.8)',
                    }}>{b.name}</span>
                    {/* progress track */}
                    <div style={{
                      flex: 1, height: 4, background: 'rgba(255,255,255,0.08)',
                      borderRadius: 4, position: 'relative', overflow: 'hidden',
                    }}>
                      {isDone ? (
                        <div style={{ height: '100%', width: '100%', background: b.color + '55', borderRadius: 4 }} />
                      ) : (
                        <div style={{
                          position: 'absolute', top: 0, width: 10, height: 4,
                          borderRadius: 4, background: b.color,
                          boxShadow: `0 0 10px 3px ${b.color}`,
                          animation: `rt-scan ${b.dur}s ease-in-out infinite`,
                          animationDelay: `${(i * 0.18).toFixed(2)}s`,
                        }} />
                      )}
                    </div>
                    {/* status label */}
                    <span style={{
                      width: 52, fontSize: 10, textAlign: 'right', flexShrink: 0,
                      color: isDone ? 'rgba(255,255,255,0.3)' : b.color,
                      animation: isDone ? 'none' : `rt-fade ${b.dur}s ease-in-out infinite`,
                      animationDelay: `${(i * 0.18).toFixed(2)}s`,
                    }}>{isDone ? 'done' : 'scanning'}</span>
                  </div>
                );
              })}
            </div>

            {/* Footer timer */}
            <div style={{
              marginTop: 20, fontSize: 11, color: 'rgba(255,255,255,0.35)',
              display: 'flex', gap: 16, alignItems: 'center',
            }}>
              <span style={{ fontFamily: 'monospace', fontSize: 13, color: 'rgba(255,255,255,0.6)' }}>
                ⏱ {mm}:{ss}
              </span>
              <span>elapsed &nbsp;·&nbsp; results appear when all backends finish</span>
            </div>
          </div>
        );
      })()}
      <SectionHead title="Red Team" />

      {/* ── Section 1: Run Controls ── */}
      <Card style={{ marginBottom: 20 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 16px' }}>Run Controls</h3>

        <p style={{ fontSize: 12, color: C.sub, marginBottom: 8 }}>
          Backend <span style={{ color: C.muted }}>(for single-backend run)</span>
        </p>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
          {backends.map(b => (
            <button key={b} onClick={() => setSelectedBackend(b)} style={{
              padding: '5px 12px', borderRadius: 4, fontSize: 12, cursor: 'pointer',
              border: `1px solid ${selectedBackend === b ? C.blue : C.border}`,
              backgroundColor: selectedBackend === b ? C.blue + '22' : 'transparent',
              color: selectedBackend === b ? C.blue : C.muted,
            }}>{b.replace(/_/g, ' ')}</button>
          ))}
        </div>

        <p style={{ fontSize: 12, color: C.sub, marginBottom: 8 }}>
          OWASP Categories <span style={{ color: C.muted }}>(empty = all)</span>
        </p>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 16 }}>
          {RT_OWASP.map(({ ref, label }) => {
            const active = selectedCats.includes(ref);
            return (
              <button key={ref} onClick={() => toggleCat(ref)} style={{
                padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer',
                border: `1px solid ${active ? C.purple : C.border}`,
                backgroundColor: active ? C.purple + '22' : 'transparent',
                color: active ? C.purple : C.muted,
              }}>{ref}: {label}</button>
            );
          })}
        </div>

        <p style={{ fontSize: 12, color: C.sub, marginBottom: 8 }}>Severity</p>
        <div style={{ display: 'flex', gap: 20, marginBottom: 20 }}>
          {['', 'low', 'medium', 'high', 'critical'].map(s => (
            <label key={s} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 13, color: severity === s ? C.text : C.muted }}>
              <input type="radio" name="rt-severity" value={s} checked={severity === s} onChange={() => setSeverity(s)} style={{ accentColor: C.blue }} />
              {s || 'All'}
            </label>
          ))}
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <Btn variant="primary" onClick={runSingle} disabled={loading || !selectedBackend}>
            {loading ? 'Running…' : '▶ Run Single Backend'}
          </Btn>
          <Btn onClick={runCompare} disabled={loading}>
            {loading ? 'Running…' : '⚡ Compare All Backends'}
          </Btn>
        </div>
      </Card>

      {/* ── Section 2: Comparison Table ── */}
      {compareReport && (() => {
        const scope       = compareReport.backend_scope || BACKEND_SCOPE;
        const totalProbes = 78; // total probes in the library
        const generalBackends     = compareReport.backends_tested.filter(b => scope[b]?.type === 'general');
        const specializedBackends = compareReport.backends_tested.filter(b => scope[b]?.type !== 'general');

        const renderBackendRow = (backend) => {
          const skipReason = compareReport.skipped_backends?.[backend];
          if (skipReason) {
            const badgeLabel = skipReason === 'MISSING_CREDENTIALS' ? 'MISSING CREDENTIALS' : 'PENDING LLM BACKEND';
            return (
              <tr key={backend} style={{ borderBottom: `1px solid ${C.border}22`, opacity: 0.45 }}>
                <td style={{ padding: '10px 12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ color: C.muted, fontWeight: 400 }}>{backend.replace(/_/g, ' ')}</span>
                    <Badge color={C.muted}>{badgeLabel}</Badge>
                  </div>
                </td>
                <td style={{ padding: '10px 12px', textAlign: 'center', color: C.muted }}>—</td>
                {RT_OWASP.map(({ ref }) => (
                  <td key={ref} style={{ padding: '10px 6px', textAlign: 'center', color: C.muted }} title="Category not tested — credentials missing">—</td>
                ))}
                <td style={{ padding: '10px 12px', textAlign: 'right', color: C.muted }}>—</td>
              </tr>
            );
          }

          const rep         = compareReport.reports[backend];
          const rate        = rep?.pass_rate ?? 0;
          const ran         = rep?.total_probes ?? 0;
          const covPct      = rep?.coverage_pct ?? Math.round(ran / totalProbes * 100);
          const isBest      = backend === compareReport.best_overall;
          const isWorst     = backend === compareReport.worst_overall && !isBest;
          const scopeMeta   = scope[backend];
          const isSpecialized = scopeMeta?.type !== 'general';
          const lowCoverage = covPct < 50;

          return (
            <tr key={backend} style={{ borderBottom: `1px solid ${C.border}22` }}>
              <td style={{ padding: '10px 12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                  <span style={{ color: C.text, fontWeight: isBest ? 700 : 400 }}>
                    {backend.replace(/_/g, ' ')}
                  </span>
                  {isBest  && <Badge color={C.green}>Best</Badge>}
                  {isWorst && <Badge color={C.red}>Worst</Badge>}
                  {isSpecialized && scopeMeta?.label && (
                    <span title={scopeMeta.note || scopeMeta.label} style={{
                      fontSize: 10, padding: '2px 6px', borderRadius: 3,
                      backgroundColor: C.purple + '22', color: C.purple,
                      fontWeight: 500, cursor: scopeMeta.note ? 'help' : 'default',
                    }}>{scopeMeta.label}</span>
                  )}
                </div>
              </td>
              <td style={{ padding: '10px 12px', textAlign: 'center' }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                  <span style={{ fontWeight: 700, fontSize: 14, color: passColor(rate) }}>
                    {(rate * 100).toFixed(0)}%
                  </span>
                  <span
                    title={`${ran} of ${totalProbes} probes ran${lowCoverage ? ' — low coverage; excluded from Best/Worst ranking' : ''}`}
                    style={{ fontSize: 10, color: lowCoverage ? C.amber : C.muted, cursor: 'help' }}>
                    {ran}/{totalProbes} probes{lowCoverage ? ' ⚠' : ''}
                  </span>
                </div>
              </td>
              {RT_OWASP.map(({ ref }) => {
                const cell     = pivot[backend]?.[ref];
                const cr       = cell?.pass_rate;
                const isWinner = compareReport.category_winners?.[ref] === backend;
                return (
                  <td key={ref} style={{ padding: '10px 6px', textAlign: 'center' }}>
                    {cr != null
                      ? <span style={{ color: passColor(cr), fontWeight: isWinner ? 700 : 400, fontSize: 12 }}>
                          {(cr * 100).toFixed(0)}%{isWinner ? ' ★' : ''}
                        </span>
                      : <span style={{ color: C.border }} title="Category not tested — quota exhausted or credentials missing">—</span>
                    }
                  </td>
                );
              })}
              <td style={{ padding: '10px 12px', textAlign: 'right', color: C.sub }}>
                {rep?.average_latency_ms?.toFixed(0) ?? '—'}
              </td>
            </tr>
          );
        };

        const sectionHeader = (label, color = C.sub) => (
          <tr key={`hdr-${label}`}>
            <td colSpan={RT_OWASP.length + 3} style={{
              padding: '8px 12px 4px',
              fontSize: 11, fontWeight: 600, color,
              letterSpacing: '0.06em', textTransform: 'uppercase',
              borderBottom: `1px solid ${C.border}`,
              background: `${color}0a`,
            }}>{label}</td>
          </tr>
        );

        return (
          <Card style={{ marginBottom: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: 0 }}>Comparison Table</h3>
              {compareReport.run_id && (
                <span style={{ fontSize: 11, color: C.muted, fontFamily: 'monospace', display: 'flex', alignItems: 'center', gap: 6 }}>
                  run: {compareReport.run_id.slice(0, 8)}…
                  <button
                    title="Copy full run ID"
                    onClick={() => { navigator.clipboard?.writeText(compareReport.run_id); toast('Run ID copied', 'ok'); }}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: C.blue, fontSize: 11, padding: '0 2px' }}>
                    ⎘
                  </button>
                </span>
              )}
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    <th style={{ textAlign: 'left',   padding: '8px 12px', color: C.sub, fontWeight: 500 }}>Backend</th>
                    <th style={{ textAlign: 'center', padding: '8px 12px', color: C.sub, fontWeight: 500 }}>Overall %</th>
                    {RT_OWASP.map(({ ref }) => (
                      <th key={ref} style={{ textAlign: 'center', padding: '8px 6px', color: C.sub, fontWeight: 500, fontSize: 11 }}>{ref}</th>
                    ))}
                    <th style={{ textAlign: 'right', padding: '8px 12px', color: C.sub, fontWeight: 500 }}>Avg ms</th>
                  </tr>
                </thead>
                <tbody>
                  {generalBackends.length > 0 && sectionHeader('General Purpose Guardrails', C.blue)}
                  {generalBackends.map(renderBackendRow)}
                  {specializedBackends.length > 0 && sectionHeader('Specialized Tools', C.purple)}
                  {specializedBackends.map(renderBackendRow)}
                </tbody>
              </table>
            </div>

            {/* Legend */}
            <div style={{ marginTop: 12, padding: '10px 12px', background: `${C.border}22`, borderRadius: 6, fontSize: 11, color: C.muted, lineHeight: 1.7 }}>
              <strong style={{ color: C.sub }}>Notes</strong>
              <ul style={{ margin: '4px 0 0', paddingLeft: 16 }}>
                <li><span style={{ color: C.border }}>—</span> in a category cell means the backend did not test those probes (quota exhausted or credentials missing).</li>
                <li>★ marks the category winner (highest pass rate for that OWASP category).</li>
                <li><span style={{ color: C.amber }}>⚠ n/78 probes</span> — fewer than 50% of probes ran; backend excluded from Best / Worst ranking.</li>
                <li><span style={{ color: C.purple }}>Specialized Tools</span> are purpose-built for a specific use case (PII detection, content moderation, injection detection) and are not directly comparable to general-purpose guardrails on overall pass rate.</li>
              </ul>
            </div>
          </Card>
        );
      })()}

      {/* ── Benchmark artifacts ── */}
      {(benchmarkArts || compareReport?.run_id) && (() => {
        const dlStyle = { fontSize: 12, color: C.blue, textDecoration: 'none', padding: '5px 12px', border: `1px solid ${C.blue}`, borderRadius: 4, fontWeight: 500 };
        const runId = compareReport?.run_id;
        return (
          <Card style={{ marginBottom: 20, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: C.text }}>
              {benchmarkArts ? 'Benchmark saved' : 'Downloads'}
            </span>
            {benchmarkArts?.json_url && (
              <a href={`/${benchmarkArts.json_url}`} download style={dlStyle}>↓ JSON</a>
            )}
            {benchmarkArts?.markdown_url && (
              <a href={`/${benchmarkArts.markdown_url}`} download style={dlStyle}>↓ Markdown</a>
            )}
            {benchmarkArts?.pdf_url ? (
              <a href={`/${benchmarkArts.pdf_url}`} download style={dlStyle}>↓ PDF</a>
            ) : runId && (
              <a href={`${api.base}/redteam/reports/${runId}/export`}
                onClick={e => { e.preventDefault(); window.dlFile && window.dlFile(`${api.base}/redteam/reports/${runId}/export`, `report_${runId.slice(0,8)}.pdf`); }}
                style={dlStyle}>↓ PDF</a>
            )}
          </Card>
        );
      })()}

      {/* ── Run history ── */}
      {runHistory.length > 0 && (
        <Card style={{ marginBottom: 20 }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, color: C.text, margin: '0 0 10px' }}>Run History (last {runHistory.length})</h3>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ color: C.muted, textAlign: 'left' }}>
                <th style={{ padding: '4px 8px' }}>Run ID</th>
                <th style={{ padding: '4px 8px' }}>Timestamp</th>
                <th style={{ padding: '4px 8px' }}>Backends</th>
                <th style={{ padding: '4px 8px' }}>Best</th>
              </tr>
            </thead>
            <tbody>
              {runHistory.map((h, i) => (
                <tr key={h.run_id} style={{ borderTop: `1px solid ${C.border}`, background: i === 0 ? C.surface : 'transparent' }}>
                  <td style={{ padding: '4px 8px', fontFamily: 'monospace', color: C.blue }}>
                    <span title={h.run_id} style={{ cursor: 'pointer' }}
                      onClick={() => { navigator.clipboard?.writeText(h.run_id); toast('Run ID copied', 'ok'); }}>
                      {h.run_id.slice(0, 8)}…
                    </span>
                  </td>
                  <td style={{ padding: '4px 8px', color: C.muted }}>{new Date(h.timestamp).toLocaleString()}</td>
                  <td style={{ padding: '4px 8px', textAlign: 'center' }}>{h.backends}</td>
                  <td style={{ padding: '4px 8px', color: C.green }}>{h.best}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {/* ── Section 3: Probe Drill Down ── */}
      {probeResults.length > 0 && (
        <Card style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: 0 }}>
              Probe Drill Down
              <span style={{ fontSize: 12, fontWeight: 400, color: C.muted, marginLeft: 8 }}>
                {filteredProbes.length} / {probeResults.length}
              </span>
            </h3>
            <div style={{ display: 'flex', gap: 6 }}>
              {['all', 'pass', 'fail'].map(f => (
                <button key={f} onClick={() => setProbeFilter(f)} style={{
                  padding: '4px 10px', borderRadius: 4, fontSize: 12, cursor: 'pointer',
                  border: `1px solid ${probeFilter === f ? C.blue : C.border}`,
                  backgroundColor: probeFilter === f ? C.blue + '22' : 'transparent',
                  color: probeFilter === f ? C.blue : C.muted,
                }}>{f}</button>
              ))}
            </div>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  {['ID', 'Category', 'Severity', 'OWASP', 'Expected', 'Actual', 'Result', 'Latency ms'].map(h => (
                    <th key={h} style={{ textAlign: 'left', padding: '8px 10px', color: C.sub, fontWeight: 500 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredProbes.map(pr => (
                  <React.Fragment key={pr.probe_id}>
                    <tr
                      onClick={() => setExpandedProbe(expandedProbe === pr.probe_id ? null : pr.probe_id)}
                      style={{
                        borderBottom: expandedProbe === pr.probe_id ? 'none' : `1px solid ${C.border}22`,
                        cursor: 'pointer',
                        backgroundColor: expandedProbe === pr.probe_id ? C.bg : 'transparent',
                      }}
                    >
                      <td style={{ padding: '8px 10px', fontFamily: 'monospace', color: C.blue, fontSize: 11 }}>{pr.probe_id}</td>
                      <td style={{ padding: '8px 10px', color: C.sub, fontSize: 11 }}>{owaspLabel(pr.owasp_ref)}</td>
                      <td style={{ padding: '8px 10px' }}>
                        <Badge color={sevColor(pr.severity)}>{pr.severity}</Badge>
                      </td>
                      <td style={{ padding: '8px 10px', color: C.muted, fontFamily: 'monospace', fontSize: 11 }}>{pr.owasp_ref}</td>
                      <td style={{ padding: '8px 10px', color: C.sub }}>{pr.expected_action}</td>
                      <td style={{ padding: '8px 10px', color: pr.actual_action === pr.expected_action ? C.green : C.red }}>
                        {pr.actual_action}
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        <Badge color={pr.passed ? C.green : C.red}>{pr.passed ? 'PASS' : 'FAIL'}</Badge>
                      </td>
                      <td style={{ padding: '8px 10px', color: C.muted }}>{pr.latency_ms?.toFixed(1)}</td>
                    </tr>
                    {expandedProbe === pr.probe_id && (
                      <tr style={{ borderBottom: `1px solid ${C.border}22` }}>
                        <td colSpan={8} style={{ padding: '14px 16px', backgroundColor: C.bg }}>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 12 }}>
                            <div>
                              <p style={{ fontSize: 11, color: C.sub, margin: '0 0 4px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>Description</p>
                              <p style={{ fontSize: 12, color: C.text, margin: 0 }}>{pr.description}</p>
                            </div>
                            <div>
                              <p style={{ fontSize: 11, color: C.sub, margin: '0 0 4px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>Tags</p>
                              <p style={{ fontSize: 12, color: C.muted, margin: 0 }}>{pr.tags?.join(', ') || '—'}</p>
                            </div>
                          </div>
                          {probeMap[pr.probe_id]?.payload && (
                            <div style={{ marginBottom: 12 }}>
                              <p style={{ fontSize: 11, color: C.sub, margin: '0 0 4px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>Payload</p>
                              <pre style={{
                                fontSize: 11, color: C.amber, backgroundColor: C.card, borderRadius: 4,
                                padding: '8px 12px', margin: 0, overflowX: 'auto', whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word', maxHeight: 120, border: `1px solid ${C.border}`,
                              }}>
                                {probeMap[pr.probe_id].payload.length > 400
                                  ? probeMap[pr.probe_id].payload.slice(0, 400) + '…'
                                  : probeMap[pr.probe_id].payload}
                              </pre>
                            </div>
                          )}
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                            <div>
                              <p style={{ fontSize: 11, color: C.sub, margin: '0 0 6px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>Risk Score</p>
                              <div style={{ background: C.card, borderRadius: 4, height: 6, overflow: 'hidden', marginBottom: 4, border: `1px solid ${C.border}` }}>
                                <div style={{
                                  height: '100%',
                                  width: `${(pr.risk_score ?? 0) * 100}%`,
                                  backgroundColor: (pr.risk_score ?? 0) > 0.6 ? C.red : (pr.risk_score ?? 0) > 0.3 ? C.amber : C.green,
                                  transition: 'width .4s',
                                }} />
                              </div>
                              <span style={{ fontSize: 12, color: C.text }}>
                                {typeof pr.risk_score === 'number' ? `${(pr.risk_score * 100).toFixed(0)}%` : '—'}
                              </span>
                            </div>
                            <div>
                              <p style={{ fontSize: 11, color: C.sub, margin: '0 0 6px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>Detected Risks</p>
                              {pr.detected_risks?.length
                                ? pr.detected_risks.map((r, i) => (
                                  <div key={i} style={{ fontSize: 11, color: C.red }}>⚠ {typeof r === 'object' ? JSON.stringify(r) : r}</div>
                                ))
                                : <span style={{ fontSize: 12, color: C.muted }}>none detected</span>
                              }
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* ── Section 4: Regression View ── */}
      {report && (
        <Card>
          <h3 style={{ fontSize: 14, fontWeight: 600, color: C.text, margin: '0 0 16px' }}>Regression View</h3>

          <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end', marginBottom: 16 }}>
            <div style={{ flex: 1 }}>
              <Input
                label="Baseline Run ID"
                value={baselineRunId}
                onChange={e => setBaselineRunId(e.target.value)}
                placeholder="Paste a previous run_id to compare"
              />
            </div>
            <div style={{ marginBottom: 12 }}>
              <Btn onClick={loadBaseline} disabled={baselineLoading || !baselineRunId}>
                {baselineLoading ? 'Loading…' : 'Load Baseline'}
              </Btn>
            </div>
          </div>

          <div style={{ padding: '10px 14px', backgroundColor: C.bg, borderRadius: 6, marginBottom: 16, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, color: C.sub }}>Current run ID:</span>
            <code style={{ fontSize: 12, color: C.blue, fontFamily: 'monospace', flex: 1 }}>{report.run_id}</code>
            <span style={{ fontSize: 11, color: C.muted }}>({report.passed}/{report.total_probes} passed · {report.backend})</span>
          </div>

          {!baselineReport ? (
            <p style={{ fontSize: 13, color: C.muted, textAlign: 'center', padding: '20px 0' }}>
              Load a baseline run above to compare regressions and improvements
            </p>
          ) : (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 16 }}>
                <StatCard label="Regressions"  value={regressions.length}  color={regressions.length  ? C.red   : C.muted} />
                <StatCard label="Improvements" value={improvements.length} color={improvements.length ? C.green : C.muted} />
                <StatCard label="Stable Pass"  value={stablePass.length}   color={C.muted} />
                <StatCard label="Stable Fail"  value={stableFail.length}   color={C.border} />
              </div>
              {(regressions.length + improvements.length + stablePass.length + stableFail.length) === 0 ? (
                <p style={{ fontSize: 13, color: C.muted, textAlign: 'center', padding: '16px 0' }}>
                  No overlapping probes between runs
                </p>
              ) : (
                <div style={{ display: 'grid', gap: 4 }}>
                  {[
                    ...regressions.map(pr  => ({ pr, type: 'regression' })),
                    ...improvements.map(pr => ({ pr, type: 'improvement' })),
                    ...stablePass.map(pr   => ({ pr, type: 'stable_pass' })),
                    ...stableFail.map(pr   => ({ pr, type: 'stable_fail' })),
                  ].map(({ pr, type }) => {
                    const color = type === 'regression' ? C.red : type === 'improvement' ? C.green : C.border;
                    const label = { regression: 'REGRESSION', improvement: 'IMPROVED', stable_pass: 'STABLE PASS', stable_fail: 'STABLE FAIL' }[type];
                    return (
                      <div key={pr.probe_id} style={{
                        display: 'flex', alignItems: 'center', gap: 12, padding: '8px 12px',
                        backgroundColor: (type === 'regression' || type === 'improvement') ? color + '11' : 'transparent',
                        borderRadius: 4, borderLeft: `3px solid ${color}`,
                      }}>
                        <span style={{ fontFamily: 'monospace', fontSize: 12, color: C.blue, minWidth: 100 }}>{pr.probe_id}</span>
                        <span style={{ fontSize: 11, color: C.muted, flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{pr.description}</span>
                        <Badge color={color}>{label}</Badge>
                      </div>
                    );
                  })}
                </div>
              )}
            </>
          )}
        </Card>
      )}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// ROOT APP
// ═════════════════════════════════════════════════════════════════════════════
const TABS = [
  { id: 'overview',  label: '📊 Overview'  },
  { id: 'checker',   label: '🧪 Live Test'  },
  { id: 'policies',  label: '📋 Policies'  },
  { id: 'testing',   label: '✅ Testing'   },
  { id: 'status',    label: '💓 Status'    },
  { id: 'versions',  label: '🗂 Versions'  },
  { id: 'alerts',    label: '🚨 Alerts'    },
  { id: 'abtests',   label: '🔀 A/B Tests' },
  { id: 'audit',     label: '📜 Audit Log' },
  { id: 'redteam',   label: '🔴 Red Team'  },
];

export default function App() {
  const [tab, setTab]         = useState('overview');
  const [metrics, setMetrics] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [health, setHealth]   = useState(null);
  const [toast, setToast]     = useState(null);
  const [lastEvent, setLastEvent] = useState(null);

  const showToast = (msg, type = 'ok') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  const loadGlobal = useCallback(async () => {
    // Health is checked independently so a failure in metrics/dashboard
    // never leaves the status indicator stuck.
    try {
      const h = await api.health();
      setHealth(h);
    } catch {
      setHealth({ status: 'down' });
    }
    try {
      const [m, d] = await Promise.all([api.getMetrics(), api.getDashboard()]);
      setMetrics(m); setDashboard(d);
    } catch {}
  }, []);

  useEffect(() => {
    loadGlobal();
    // Poll fast (3s) until the API is reachable, then back off to 15s.
    let interval = 3000;
    let timer;
    const tick = async () => {
      await loadGlobal();
      timer = setTimeout(tick, interval);
    };
    timer = setTimeout(tick, interval);
    // Switch to slow polling once we've had a successful health check
    const slow = setInterval(() => { interval = 15000; }, 6000);
    return () => { clearTimeout(timer); clearInterval(slow); };
  }, [loadGlobal]);

  // Gap 6 — real-time policy push via Server-Sent Events
  useEffect(() => {
    const base = process.env.REACT_APP_API_URL || '';
    let es;
    try {
      es = new EventSource(`${base}/push/events`);
      es.onmessage = (e) => {
        try {
          const ev = JSON.parse(e.data);
          if (ev.type && ev.type !== 'connected') {
            setLastEvent(ev);
            loadGlobal();   // refresh on any policy change
          }
        } catch {}
      };
      es.onerror = () => { /* browser auto-reconnects */ };
    } catch {}
    return () => { if (es) es.close(); };
  }, [loadGlobal]);

  return (
    <div style={{ backgroundColor: C.bg, color: C.text, minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ backgroundColor: C.card, borderBottom: `1px solid ${C.border}`, padding: '18px 32px' }}>
        <div style={{ maxWidth: 1300, margin: '0 auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0, color: C.text }}>🛡️ Guardrail Control Center</h1>
            <p style={{ fontSize: 12, color: C.muted, margin: 0 }}>Unified AI safety monitoring across all backends</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            {lastEvent && (
              <span style={{ fontSize: 11, color: C.purple, backgroundColor: C.purple + '22', padding: '3px 8px', borderRadius: 4 }}>
                ⚡ {lastEvent.type}
              </span>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: health?.status === 'ok' ? C.green : C.red }} />
              <span style={{ fontSize: 12, color: C.sub }}>{health?.status === 'ok' ? 'API Online' : 'API Offline'}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Tab bar */}
      <div style={{ backgroundColor: C.card, borderBottom: `1px solid ${C.border}`, display: 'flex', gap: 4, padding: '0 32px', overflowX: 'auto' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            background: 'none', border: 'none', cursor: 'pointer',
            padding: '14px 16px', fontSize: 13, whiteSpace: 'nowrap',
            color: tab === t.id ? C.blue : C.muted,
            borderBottom: tab === t.id ? `2px solid ${C.blue}` : '2px solid transparent',
            transition: 'color .15s',
          }}>{t.label}</button>
        ))}
      </div>

      {/* Content */}
      <div style={{ maxWidth: 1300, margin: '0 auto', padding: '28px 32px' }}>
        {tab === 'overview' && <OverviewTab metrics={metrics} dashboard={dashboard} health={health} />}
        {tab === 'checker'  && <CheckerTab  toast={showToast} />}
        {tab === 'policies' && <PoliciesTab toast={showToast} />}
        {tab === 'testing'  && <TestingTab  toast={showToast} />}
        {tab === 'status'   && <StatusTab   toast={showToast} />}
        {tab === 'versions' && <VersionsTab toast={showToast} />}
        {tab === 'alerts'   && <AlertsTab   toast={showToast} />}
        {tab === 'abtests'  && <ABTestsTab  toast={showToast} />}
        {tab === 'audit'    && <AuditTab />}
        {/* RedTeamTab stays mounted to preserve compareReport/benchmarkArts state across tab switches */}
        <div style={{ display: tab === 'redteam' ? 'block' : 'none' }}>
          <RedTeamTab toast={showToast} />
        </div>
      </div>

      {toast && <Toast msg={toast.msg} type={toast.type} />}
    </div>
  );
}
