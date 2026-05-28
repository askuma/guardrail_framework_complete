import React, { useState, useEffect } from 'react';
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const GuardrailDashboard = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [policies, setPolicies] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [abTests, setAbTests] = useState([]);

  // Simulated data - replace with actual API calls
  const mockMetricsData = [
    { time: '00:00', checkCount: 120, passRate: 85, avgLatency: 45 },
    { time: '04:00', checkCount: 150, passRate: 82, avgLatency: 52 },
    { time: '08:00', checkCount: 280, passRate: 88, avgLatency: 48 },
    { time: '12:00', checkCount: 450, passRate: 84, avgLatency: 55 },
    { time: '16:00', checkCount: 320, passRate: 90, avgLatency: 42 },
    { time: '20:00', checkCount: 200, passRate: 86, avgLatency: 50 },
  ];

  const mockPolicies = [
    { id: 'pol_001', name: 'Production Chat', backend: 'guardrails_ai', status: 'active', riskCategories: 4 },
    { id: 'pol_002', name: 'Privacy Focused', backend: 'presidio', status: 'active', riskCategories: 2 },
    { id: 'pol_003', name: 'Agent Execution', backend: 'nemo', status: 'active', riskCategories: 3 },
  ];

  const mockAlerts = [
    { id: 'alert_001', type: 'HIGH_BLOCK_RATE', severity: 'warning', title: 'Block rate elevated', value: '32%', threshold: '30%' },
    { id: 'alert_002', type: 'LATENCY_SPIKE', severity: 'warning', title: 'Latency increase detected', value: '520ms', threshold: '500ms' },
  ];

  const mockBackendHealth = [
    { name: 'NeMo', latency: 48, slaStatus: 'green', checks: 1240 },
    { name: 'GuardrailsAI', latency: 45, slaStatus: 'green', checks: 2850 },
    { name: 'Presidio', latency: 52, slaStatus: 'yellow', checks: 980 },
  ];

  const mockRiskDistribution = [
    { name: 'Prompt Injection', value: 35, fill: '#ef4444' },
    { name: 'Data Leakage', value: 28, fill: '#f97316' },
    { name: 'Jailbreaking', value: 20, fill: '#eab308' },
    { name: 'Other', value: 17, fill: '#06b6d4' },
  ];

  useEffect(() => {
    setPolicies(mockPolicies);
    setAlerts(mockAlerts);
  }, []);

  return (
    <div style={{ backgroundColor: '#0f172a', color: '#e2e8f0', minHeight: '100vh', fontFamily: '"Anthropic Sans", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif' }}>
      {/* Header */}
      <div style={{ backgroundColor: '#1e293b', borderBottom: '1px solid #334155', padding: '20px 32px' }}>
        <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
          <h1 style={{ fontSize: '28px', fontWeight: '600', margin: '0 0 8px 0', color: '#f1f5f9' }}>
            🛡️ Guardrail Control Center
          </h1>
          <p style={{ fontSize: '14px', color: '#94a3b8', margin: 0 }}>
            Real-time monitoring of AI safety guardrails across all backends
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ backgroundColor: '#1e293b', borderBottom: '1px solid #334155', display: 'flex', gap: '32px', padding: '0 32px' }}>
        {['overview', 'policies', 'alerts', 'abtest'].map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              backgroundColor: 'transparent',
              border: 'none',
              color: activeTab === tab ? '#38bdf8' : '#64748b',
              padding: '16px 0',
              fontSize: '14px',
              fontWeight: activeTab === tab ? '500' : '400',
              cursor: 'pointer',
              borderBottom: activeTab === tab ? '2px solid #38bdf8' : 'none',
              transition: 'all 0.2s'
            }}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{ maxWidth: '1400px', margin: '0 auto', padding: '32px' }}>
        
        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div>
            {/* Key Metrics */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px', marginBottom: '32px' }}>
              {[
                { label: 'Total Checks', value: '12,450', change: '+12%', color: '#38bdf8' },
                { label: 'Pass Rate', value: '87.2%', change: '+2.1%', color: '#10b981' },
                { label: 'Avg Latency', value: '49ms', change: '-8%', color: '#8b5cf6' },
                { label: 'Blocked', value: '1,597', change: '+5%', color: '#ef4444' },
              ].map((metric, idx) => (
                <div key={idx} style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '8px', border: '1px solid #334155' }}>
                  <p style={{ fontSize: '12px', color: '#94a3b8', margin: '0 0 8px 0' }}>{metric.label}</p>
                  <p style={{ fontSize: '28px', fontWeight: '600', margin: '0 0 12px 0', color: metric.color }}>{metric.value}</p>
                  <p style={{ fontSize: '12px', color: '#10b981', margin: 0 }}>{metric.change} vs 24h</p>
                </div>
              ))}
            </div>

            {/* Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '20px', marginBottom: '32px' }}>
              {/* Check Volume & Pass Rate Trend */}
              <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '8px', border: '1px solid #334155' }}>
                <h3 style={{ fontSize: '16px', fontWeight: '600', margin: '0 0 16px 0', color: '#f1f5f9' }}>Checks & Pass Rate (24h)</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={mockMetricsData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis dataKey="time" stroke="#64748b" />
                    <YAxis yAxisId="left" stroke="#64748b" />
                    <YAxis yAxisId="right" orientation="right" stroke="#64748b" />
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '6px' }} />
                    <Legend />
                    <Line yAxisId="left" type="monotone" dataKey="checkCount" stroke="#38bdf8" name="Check Count" />
                    <Line yAxisId="right" type="monotone" dataKey="passRate" stroke="#10b981" name="Pass Rate %" />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              {/* Risk Distribution */}
              <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '8px', border: '1px solid #334155' }}>
                <h3 style={{ fontSize: '16px', fontWeight: '600', margin: '0 0 16px 0', color: '#f1f5f9' }}>Risk Distribution</h3>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie data={mockRiskDistribution} cx="50%" cy="50%" innerRadius={60} outerRadius={100} paddingAngle={2} dataKey="value">
                      {mockRiskDistribution.map((entry, idx) => (
                        <Cell key={`cell-${idx}`} fill={entry.fill} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: '6px' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Backend Health */}
            <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '8px', border: '1px solid #334155', marginBottom: '32px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: '600', margin: '0 0 16px 0', color: '#f1f5f9' }}>Backend Health Status</h3>
              <div style={{ display: 'grid', gap: '12px' }}>
                {mockBackendHealth.map((backend, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '16px', padding: '12px', backgroundColor: '#0f172a', borderRadius: '6px' }}>
                    <div style={{ flex: 1 }}>
                      <p style={{ fontSize: '14px', fontWeight: '500', margin: '0 0 4px 0', color: '#f1f5f9' }}>{backend.name}</p>
                      <p style={{ fontSize: '12px', color: '#64748b', margin: 0 }}>{backend.checks.toLocaleString()} checks</p>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <div style={{ fontSize: '12px', color: '#94a3b8' }}>{backend.latency}ms</div>
                      <div style={{
                        width: '12px',
                        height: '12px',
                        borderRadius: '50%',
                        backgroundColor: backend.slaStatus === 'green' ? '#10b981' : '#f59e0b',
                      }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Policies Tab */}
        {activeTab === 'policies' && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <h2 style={{ fontSize: '20px', fontWeight: '600', margin: 0, color: '#f1f5f9' }}>Active Policies</h2>
              <button style={{
                backgroundColor: '#38bdf8',
                color: '#0f172a',
                border: 'none',
                padding: '8px 16px',
                borderRadius: '6px',
                fontSize: '14px',
                fontWeight: '500',
                cursor: 'pointer'
              }}>
                + New Policy
              </button>
            </div>

            <div style={{ display: 'grid', gap: '12px' }}>
              {policies.map(policy => (
                <div key={policy.id} style={{ backgroundColor: '#1e293b', padding: '16px', borderRadius: '8px', border: '1px solid #334155', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <h3 style={{ fontSize: '14px', fontWeight: '600', margin: '0 0 4px 0', color: '#f1f5f9' }}>{policy.name}</h3>
                    <p style={{ fontSize: '12px', color: '#64748b', margin: 0 }}>Backend: <span style={{ color: '#94a3b8' }}>{policy.backend}</span> • Risk Categories: {policy.riskCategories}</p>
                  </div>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                    <span style={{ fontSize: '12px', backgroundColor: '#10b98133', color: '#10b981', padding: '4px 8px', borderRadius: '4px' }}>Active</span>
                    <button style={{ backgroundColor: 'transparent', border: '1px solid #334155', color: '#94a3b8', padding: '6px 12px', borderRadius: '4px', fontSize: '12px', cursor: 'pointer' }}>Edit</button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Alerts Tab */}
        {activeTab === 'alerts' && (
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: '600', margin: '0 0 20px 0', color: '#f1f5f9' }}>Active Alerts</h2>
            <div style={{ display: 'grid', gap: '12px' }}>
              {alerts.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '32px', color: '#64748b' }}>
                  <p>No alerts at this time</p>
                </div>
              ) : (
                alerts.map(alert => (
                  <div key={alert.id} style={{
                    backgroundColor: '#1e293b',
                    padding: '16px',
                    borderRadius: '8px',
                    border: `1px solid ${alert.severity === 'critical' ? '#ef4444' : '#f59e0b'}`,
                    borderLeft: `4px solid ${alert.severity === 'critical' ? '#ef4444' : '#f59e0b'}`,
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                      <div>
                        <h3 style={{ fontSize: '14px', fontWeight: '600', margin: '0 0 4px 0', color: '#f1f5f9' }}>{alert.title}</h3>
                        <p style={{ fontSize: '12px', color: '#64748b', margin: '0 0 8px 0' }}>{alert.type}</p>
                        <p style={{ fontSize: '12px', color: '#94a3b8', margin: 0 }}>Current: <span style={{ color: '#f1f5f9', fontWeight: '500' }}>{alert.value}</span> • Threshold: {alert.threshold}</p>
                      </div>
                      <button style={{
                        backgroundColor: 'transparent',
                        border: '1px solid #334155',
                        color: '#94a3b8',
                        padding: '6px 12px',
                        borderRadius: '4px',
                        fontSize: '12px',
                        cursor: 'pointer'
                      }}>
                        Resolve
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* A/B Test Tab */}
        {activeTab === 'abtest' && (
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: '600', margin: '0 0 20px 0', color: '#f1f5f9' }}>A/B Tests</h2>
            <div style={{ display: 'grid', gap: '20px' }}>
              {[
                { name: 'Security vs. Usability', control: 'Strict Security', experiment: 'Balanced', traffic: '50%', duration: '2d 14h' },
                { name: 'Backend Performance', control: 'NeMo', experiment: 'GuardrailsAI', traffic: '40%', duration: '1d 8h' },
              ].map((test, idx) => (
                <div key={idx} style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '8px', border: '1px solid #334155' }}>
                  <h3 style={{ fontSize: '16px', fontWeight: '600', margin: '0 0 16px 0', color: '#f1f5f9' }}>{test.name}</h3>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
                    <div>
                      <p style={{ fontSize: '12px', color: '#94a3b8', margin: '0 0 4px 0' }}>Control Group</p>
                      <p style={{ fontSize: '14px', fontWeight: '500', color: '#f1f5f9', margin: 0 }}>{test.control}</p>
                    </div>
                    <div>
                      <p style={{ fontSize: '12px', color: '#94a3b8', margin: '0 0 4px 0' }}>Experiment Group</p>
                      <p style={{ fontSize: '14px', fontWeight: '500', color: '#f1f5f9', margin: 0 }}>{test.experiment}</p>
                    </div>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <p style={{ fontSize: '12px', color: '#64748b', margin: 0 }}>Traffic Split: {test.traffic} • Time Left: {test.duration}</p>
                    <button style={{
                      backgroundColor: 'transparent',
                      border: '1px solid #334155',
                      color: '#94a3b8',
                      padding: '6px 12px',
                      borderRadius: '4px',
                      fontSize: '12px',
                      cursor: 'pointer'
                    }}>
                      View Results
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default GuardrailDashboard;
