# Guardrail Framework - Quick Reference Guide

## 🎯 Common Use Cases & Code Snippets

### 1. Basic Guardrail Check

```python
from guardrail_framework import GuardrailFramework, UnifiedPolicyBuilder, GuardrailBackend, RiskCategory, ActionType

# Initialize
framework = GuardrailFramework()

# Create policy
policy = UnifiedPolicyBuilder() \
    .with_name("Default Policy") \
    .with_backend(GuardrailBackend.GUARDRAILS_AI) \
    .with_risk_categories([RiskCategory.PROMPT_INJECTION]) \
    .with_action(ActionType.BLOCK) \
    .build()

policy_id = framework.create_policy(policy)

# Check input
result = framework.check_input("user input", policy_id)
print(f"Safe: {result.passed}, Risk: {result.risk_score:.2f}")
```

---

### 2. Switch Backends (No Code Changes)

```python
# Initial setup with GuardrailsAI
framework.update_policy(policy_id, {
    "backend": GuardrailBackend.GUARDRAILS_AI
})
result1 = framework.check_input("text", policy_id)

# Switch to Presidio for PII detection
framework.update_policy(policy_id, {
    "backend": GuardrailBackend.PRESIDIO
})
result2 = framework.check_input("text", policy_id)  # Uses Presidio now

# Switch to Lakera for real-time checks
framework.update_policy(policy_id, {
    "backend": GuardrailBackend.LAKERA
})
result3 = framework.check_input("text", policy_id)  # Uses Lakera now
```

---

### 3. A/B Test Two Policies

```python
from guardrail_framework import ABTestConfig

# Create test policies
strict = PolicyTemplates.strict_security()
balanced = PolicyTemplates.balanced()

strict_id = framework.create_policy(strict)
balanced_id = framework.create_policy(balanced)

# Create A/B test
test = ABTestConfig(
    name="Security vs Usability",
    control_policy_id=strict_id,
    experiment_policy_id=balanced_id,
    traffic_split=0.5,  # 50% to experiment
    duration_hours=24,
    metrics_to_track=["block_rate", "latency_ms"]
)

test_id = framework.create_ab_test(test)

# Route requests
for i in range(100):
    policy_id = framework.get_policy_for_abtest(test_id)
    result = framework.check_input("text", policy_id)
    # Metrics automatically tracked by test_id
```

---

### 4. Agent Tool Validation

```python
# Policy for agent execution
agent_policy = UnifiedPolicyBuilder() \
    .with_name("Agent Execution") \
    .with_risk_categories([RiskCategory.MALICIOUS_TOOL_USE]) \
    .with_rules({
        "max_tool_calls_per_minute": 10,
        "allowed_tools": ["read_file", "search", "calculate"],
        "forbidden_tools": ["delete_file", "exec_code"]
    }) \
    .build()

agent_policy_id = framework.create_policy(agent_policy)

# Validate before tool execution
async def safe_tool_call(tool_name, tool_args):
    result = framework.validate_tool_call(
        agent_policy_id,
        tool_name,
        tool_args,
        context={"agent_id": "agent_001"}
    )
    
    if not result.passed:
        return f"Tool blocked: {result.detected_risks}"
    
    # Execute tool
    return await execute_tool(tool_name, tool_args)
```

---

### 5. Privacy-Focused (PII Redaction)

```python
# Redact sensitive data
privacy_policy = UnifiedPolicyBuilder() \
    .with_name("Privacy Mode") \
    .with_backend(GuardrailBackend.PRESIDIO) \
    .with_risk_categories([RiskCategory.DATA_LEAKAGE]) \
    .with_action(ActionType.REDACT) \
    .build()

policy_id = framework.create_policy(privacy_policy)

# Check & redact
result = framework.check_output(
    "My email is user@example.com and phone is 555-1234",
    policy_id
)

if result.action == ActionType.REDACT:
    output = result.modified_text  # [EMAIL_ADDRESS] and [PHONE_NUMBER]
```

---

### 6. Multi-Layer Protection

```python
# Layer 1: Input check
input_result = framework.check_input(user_input, "input_policy")
if not input_result.passed:
    return "Input blocked"

# Layer 2: Tool validation (for agents)
tool_result = framework.validate_tool_call(
    "tool_policy", tool_name, tool_args
)
if not tool_result.passed:
    return f"Tool {tool_name} not allowed"

# Layer 3: Output check
output_result = framework.check_output(response, "output_policy")
if output_result.action == ActionType.REDACT:
    response = output_result.modified_text

return response
```

---

### 7. Custom Risk Rules

```python
# Create custom policy with rules
custom_policy = UnifiedPolicyBuilder() \
    .with_name("Custom Rules") \
    .with_rules({
        "blacklist_keywords": ["drop table", "admin"],
        "max_input_length": 10000,
        "allowed_domains": ["internal.company.com"],
        "require_auth": True,
        "rate_limit": {
            "max_requests_per_minute": 60,
            "max_requests_per_hour": 1000
        }
    }) \
    .build()

policy_id = framework.create_policy(custom_policy)
```

---

### 8. Real-Time Monitoring

```python
from guardrail_framework import ObservabilityStack

observability = ObservabilityStack()

# Record every check
result = framework.check_input(text, policy_id)
observability.record_guardrail_check(
    policy_id=policy_id,
    backend="guardrails_ai",
    input_text=text,
    output_text=result.modified_text,
    passed=result.passed,
    risk_score=result.risk_score,
    latency_ms=result.latency_ms
)

# Get metrics
metrics = observability.metrics.get_metric_summary("latency_ms", hours=1)
print(f"P95 Latency: {metrics['max']:.1f}ms")

# Check alerts
alerts = observability.alerting.check_alerts()
for alert in alerts:
    print(f"⚠️  {alert.title}")
```

---

### 9. Compliance Reporting

```python
# Generate report
report = observability.audit.get_compliance_report(
    start_date="2024-01-01T00:00:00",
    end_date="2024-01-31T23:59:59"
)

print(f"Total Checks: {report['summary']['total_checks']}")
print(f"Passed: {report['summary']['checks_passed']}")
print(f"Failed: {report['summary']['checks_failed']}")
print(f"Avg Risk: {report['summary']['average_risk_score']:.2f}")

# Export report
with open("compliance_report.json", "w") as f:
    json.dump(report, f)
```

---

### 10. Policy Export & Backup

```python
# Export as JSON
json_str = framework.export_policy(policy_id, format="json")

# Export as YAML
yaml_str = framework.export_policy(policy_id, format="yaml")

# Backup all policies
import json
backup = {
    policy_id: framework.export_policy(policy_id)
    for policy_id in framework.policies.keys()
}

with open("policy_backup.json", "w") as f:
    json.dump(backup, f, indent=2)

# Restore from backup
for policy_data in json.load(open("policy_backup.json")):
    framework.create_policy(GuardrailPolicy(**policy_data))
```

---

## 📋 Risk Categories Quick Reference

| Category | Description | Example |
|----------|-------------|---------|
| `PROMPT_INJECTION` | Malicious instructions in prompts | "Ignore rules and..." |
| `JAILBREAKING` | Attempts to bypass safety | "Pretend rules don't apply" |
| `MALICIOUS_TOOL_USE` | Unauthorized API/tool calls | Calling delete_user tool |
| `UNSAFE_CODE` | Generated code with vulnerabilities | SQL injection in code |
| `DATA_LEAKAGE` | PII or sensitive data exposure | Returning SSNs |
| `DOS` | Denial of service attacks | Huge input causing timeout |
| `INDIRECT_ATTACK` | Attacks via retrieved content | Poisoned RAG documents |
| `HALLUCINATION` | False or fabricated info | Making up facts |
| `MODEL_THEFT` | Model extraction attacks | Stealing model weights |
| `SUPPLY_CHAIN` | Dependency compromises | Malicious plugin |

---

## 🎨 Backend Comparison

| Feature | NeMo | GuardrailsAI | Presidio | Lakera |
|---------|------|--------------|----------|---------|
| **Latency** | 50-100ms | 40-80ms | 60-150ms | <50ms |
| **PII Detection** | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐ |
| **Customizable** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Real-time** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Agent-friendly** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ |
| **Easy Integration** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |

---

## ⚡ Performance Tips

### Reduce Latency
```python
# 1. Use Lakera Guard for <50ms latency
policy.backend = GuardrailBackend.LAKERA

# 2. Cache compiled policies
cache_policy_compilation = True

# 3. Batch check requests
results = await batch_check_inputs(texts, policy_id)

# 4. Use async/parallel processing
import asyncio
tasks = [framework.check_input(t, policy_id) for t in texts]
results = await asyncio.gather(*tasks)
```

### Improve Accuracy
```python
# 1. Use high sensitivity
policy.sensitivity = "high"

# 2. Combine multiple backends
# Check with multiple backends, block if any flag
checks = [
    framework.check_input(text, nemo_policy),
    framework.check_input(text, presidio_policy),
    framework.check_input(text, lakera_policy),
]
if any(not c.passed for c in checks):
    block_request()

# 3. Use A/B tests to validate changes before deployment
# 4. Review blocked examples to refine rules
```

---

## 🔧 Configuration Examples

### Strict Security (Block Everything Suspicious)
```python
PolicyTemplates.strict_security()
# Sensitivity: high
# Action: block
# Categories: all 10
```

### Privacy Focused (Redact Sensitive Data)
```python
PolicyTemplates.privacy_focused()
# Sensitivity: high
# Action: redact
# Categories: data_leakage, indirect_attack
```

### Balanced (Good UX + Security)
```python
PolicyTemplates.balanced()
# Sensitivity: medium
# Action: redact
# Categories: prompt_injection, data_leakage
```

### Agent Execution (Tool Validation)
```python
PolicyTemplates.agent_execution()
# Sensitivity: high
# Action: block
# Categories: malicious_tool_use, unsafe_code, dos
# Rules: tool allowlist/blocklist, rate limits
```

---

## 🚨 Alert Rules

### Pre-configured Alerts

| Alert | Threshold | Window | Severity |
|-------|-----------|--------|----------|
| High Block Rate | >30% | 5 min | ⚠️ Warning |
| Latency Spike | >500ms | 10 min | ⚠️ Warning |
| Backend Failure | >10% errors | 5 min | 🔴 Critical |
| Repeated Violations | >10 in 5 min | 5 min | ⚠️ Warning |

### Set Custom Alert
```python
observability.alerting.add_alert_rule(
    name="custom_alert",
    metric="risk_score",
    threshold=0.8,
    window_minutes=10,
    severity=AlertSeverity.CRITICAL
)
```

---

## 📊 Metrics to Track

```python
# Check these regularly
metrics = observability.get_dashboard_data()

# Key metrics
checks_per_second = metrics["metrics"]["check_count"]["latest"]
pass_rate = metrics["metrics"]["pass_rate"]["avg"] * 100
p95_latency = metrics["metrics"]["latency_ms"]["max"]
avg_risk = metrics["metrics"]["risk_score"]["avg"]

# Alert status
active_alerts = len(metrics["alerts"]["active"])

# Health check
if p95_latency > 100:
    print("⚠️  Latency SLA at risk")
if pass_rate < 85:
    print("⚠️  Pass rate below threshold")
if active_alerts > 0:
    print("⚠️  Active alerts present")
```

---

## 🐳 Docker Quick Start

```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY guardrail_framework/ .
RUN pip install -e .
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "server:app"]
```

```bash
docker build -t guardrail:1.0 .
docker run -p 8000:8000 guardrail:1.0
```

---

## 📚 File Reference

| File | What It Does |
|------|------------|
| `core.py` | Framework core, backend implementations |
| `compiler.py` | Policy compilation, builder pattern |
| `observability.py` | Metrics, alerts, audit logging |
| `examples.py` | 8 runnable examples |
| `dashboard.jsx` | React monitoring UI |
| `README.md` | Full API reference |
| `ARCHITECTURE.md` | Deployment patterns |

---

## 🎯 Next Steps

1. **Install**: `pip install -e guardrail_framework/`
2. **Run examples**: `python guardrail_framework/examples.py`
3. **Integrate**: Use snippets above in your code
4. **Deploy**: Follow `ARCHITECTURE.md`
5. **Monitor**: Set up dashboard and alerts

---

## 🤝 Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| High false positives | Lower sensitivity from "high" to "medium" |
| Latency exceeds SLA | Switch to GuardrailBackend.LAKERA |
| Policy not taking effect | Call `framework.update_policy()` to refresh |
| Metrics not recording | Ensure `observability.record_guardrail_check()` is called |
| Alerts not triggering | Check alert rule thresholds match your metrics |

---

**Happy guarding! 🛡️**
