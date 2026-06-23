# Guardrail Framework Abstraction Layer - Complete Guide

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Core Concepts](#core-concepts)
6. [API Reference](#api-reference)
7. [Backend Integration](#backend-integration)
8. [Policy Management](#policy-management)
9. [A/B Testing](#ab-testing)
10. [Observability](#observability)
11. [Production Deployment](#production-deployment)

---

## Overview

The Guardrail Framework Abstraction Layer provides a unified interface for deploying and managing AI safety guardrails across 11 backends (NVIDIA NeMo, GuardrailsAI, Microsoft Presidio, LlamaFirewall, LLM Guard, Lakera, GA Guard, OpenAI Moderation, Azure Content Safety, Azure Prompt Shields, AWS Bedrock) without vendor lock-in.

### Key Features

✅ **Multi-backend routing** - Same policy, different backends, zero code changes  
✅ **Unified policy language** - Single format compiles to backend-specific configs  
✅ **A/B testing** - Compare guardrail policies with traffic splitting  
✅ **Comprehensive observability** - Metrics, alerts, audit logging, compliance reporting  
✅ **Agent-specific guardrails** - Tool validation, budget caps, scope enforcement  
✅ **Production-ready** - High performance, thread-safe, enterprise-grade logging  

---

## Architecture

```
┌─────────────────────────────────────────────┐
│         Application Layer                   │
│  (Chatbots, Agents, LLM Pipelines)         │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│   GuardrailFramework (Main Orchestrator)    │
│  ┌─────────────────────────────────────┐   │
│  │ Policy Management                   │   │
│  │ Backend Routing                     │   │
│  │ A/B Test Assignment                 │   │
│  └─────────────────────────────────────┘   │
└──────────────────┬──────────────────────────┘
                   │
        ┌──────────┼──────────┬────────────┐
        │          │          │            │
   ┌────▼──┐ ┌────▼──┐ ┌────▼──┐ ┌──────▼─┐ ┌──────▼──┐ ┌──────▼──┐
   │ NeMo  │ │Guardr-│ │Presidio│ │Llama   │ │LLM     │ │Lakera / │
   │Rails  │ │ailsAI │ │(PII)   │ │Firewall│ │Guard   │ │… cloud  │
   └───────┘ └───────┘ └────────┘ └────────┘ └────────┘ └─────────┘
        │          │          │         │           │           │
   Colang DSL   YAML      Config   local inf.  local inf.  REST API
        │          │          │         │           │           │
        └──────────┴──────────┴─────────┴───────────┴───────────┘
                   │
┌──────────────────▼──────────────────────────┐
│     ObservabilityStack                      │
│  ┌────────────┬──────────┬──────┬────────┐ │
│  │  Metrics   │ Alerting │Audit │Performance
│  │ Collector  │ System   │Logger│Monitor  │
│  └────────────┴──────────┴──────┴────────┘ │
└─────────────────────────────────────────────┘
```

---

## Installation

### Requirements
- Python 3.9+
- pip or poetry

### From Source

```bash
git clone https://github.com/yourorg/guardrail-framework.git
cd guardrail-framework
pip install -e .
```

### Dependencies

```bash
pip install numpy pandas pydantic fastapi uvicorn
```

---

## Quick Start

### 1. Initialize Framework

```python
from guardrail_framework.core import GuardrailFramework

framework = GuardrailFramework()
```

### 2. Create a Policy

```python
from guardrail_framework.compiler import UnifiedPolicyBuilder
from guardrail_framework.core import GuardrailBackend, RiskCategory, ActionType

policy = UnifiedPolicyBuilder() \
    .with_name("Production Chat") \
    .with_backend(GuardrailBackend.GUARDRAILS_AI) \
    .with_risk_categories([
        RiskCategory.PROMPT_INJECTION,
        RiskCategory.DATA_LEAKAGE
    ]) \
    .with_sensitivity("high") \
    .with_action(ActionType.BLOCK) \
    .build()

policy_id = framework.create_policy(policy)
```

### 3. Check Input

```python
result = framework.check_input(
    "user input to check",
    policy_id,
    context={"user_id": "user123"}
)

if result.passed:
    print("✓ Input is safe")
else:
    print(f"✗ Risk detected: {result.detected_risks}")
    print(f"Action taken: {result.action.value}")
```

### 4. Monitor with Observability

```python
from guardrail_framework.observability import ObservabilityStack

observability = ObservabilityStack()

observability.record_guardrail_check(
    policy_id=policy_id,
    backend="guardrails_ai",
    input_text="original input",
    output_text="processed output",
    passed=result.passed,
    risk_score=result.risk_score,
    latency_ms=result.latency_ms
)

# Get dashboard data
dashboard = observability.get_dashboard_data()
print(dashboard["metrics"])
```

---

## Core Concepts

### Policies

A **policy** defines what guardrails to apply. It includes:
- Risk categories to monitor (OWASP LLM Top 10)
- Sensitivity level (low/medium/high)
- Action on violation (block/redact/rewrite/escalate)
- Backend to use (NeMo, GuardrailsAI, Presidio, etc.)
- Custom rules and restrictions

### Backends

**Backends** are the underlying safety engines:

| Backend | Strengths | Best For |
|---------|-----------|----------|
| **NeMo** | State machines, conversational flows | Multi-turn dialogue guardrails |
| **GuardrailsAI** | Composable validators, structured output | Flexible, custom risk checks |
| **Presidio** | PII detection, enterprise-grade | Data privacy, compliance |
| **LlamaFirewall** | Meta PromptGuard 2; fully local, no API key | Air-gapped or cost-sensitive deployments |
| **LLM Guard** | PromptInjection + Toxicity; fully local, no API key | Self-hosted inference environments |
| **Lakera** | Real-time, ultra-low latency | High-throughput production |
| **GA Guard** | Adversarial robustness | Adversarial attack detection |

### Risk Categories (OWASP LLM Top 10)

```python
RiskCategory.PROMPT_INJECTION      # Malicious instructions in prompts
RiskCategory.JAILBREAKING          # Attempts to bypass safety measures
RiskCategory.MALICIOUS_TOOL_USE    # Unauthorized API/tool calls
RiskCategory.UNSAFE_CODE           # Generated code with security issues
RiskCategory.DATA_LEAKAGE          # PII or sensitive data exposure
RiskCategory.DOS                   # Denial of service attacks
RiskCategory.INDIRECT_ATTACK       # Attacks via retrieved content
RiskCategory.HALLUCINATION         # False or fabricated information
RiskCategory.MODEL_THEFT           # Model extraction attacks
RiskCategory.SUPPLY_CHAIN          # Dependency/plugin compromises
```

---

## API Reference

### GuardrailFramework

```python
class GuardrailFramework:
    # Policy Management
    def create_policy(policy: GuardrailPolicy) -> str
    def update_policy(policy_id: str, updates: Dict) -> bool
    def delete_policy(policy_id: str) -> bool
    
    # Guardrail Checks
    def check_input(text: str, policy_id: str, context: Dict = None) -> GuardrailResult
    def check_output(text: str, policy_id: str, context: Dict = None) -> GuardrailResult
    def validate_tool_call(policy_id: str, tool_name: str, 
                          tool_args: Dict, context: Dict = None) -> GuardrailResult
    
    # Backend Management
    def register_backend(name: str, backend: GuardrailBackendInterface)
    
    # A/B Testing
    def create_ab_test(test_config: ABTestConfig) -> str
    def get_policy_for_abtest(test_id: str) -> str
    
    # Metrics & Audit
    def get_metrics() -> Dict[str, Any]
    def get_audit_log(limit: int = 100) -> List[Dict]
    def export_policy(policy_id: str, format: str = "json") -> str
```

### GuardrailResult

```python
@dataclass
class GuardrailResult:
    passed: bool                              # Did it pass the check?
    severity: str                             # info, warning, critical
    detected_risks: List[Dict]                # Risks found
    risk_score: float                         # 0-1 normalized score
    action: ActionType                        # Action taken
    original_text: str                        # Original input/output
    modified_text: str                        # After redaction/rewrite
    backend_used: GuardrailBackend            # Which backend ran it
    latency_ms: float                         # Response time
    timestamp: str                            # ISO timestamp
    findings: Dict[str, Any]                  # Detailed detection results
```

### UnifiedPolicyBuilder

```python
builder = UnifiedPolicyBuilder()
policy = builder \
    .with_name("Policy Name") \
    .with_description("Description") \
    .with_backend(GuardrailBackend.GUARDRAILS_AI) \
    .with_risk_categories([RiskCategory.PROMPT_INJECTION]) \
    .with_sensitivity("high")  # low, medium, high \
    .with_action(ActionType.BLOCK) \
    .with_escalation_email("security@company.com") \
    .with_rules({"custom_rule": "value"}) \
    .with_tag("production") \
    .build()
```

### ObservabilityStack

```python
observability = ObservabilityStack()

# Record a check
observability.record_guardrail_check(
    policy_id, backend, input_text, output_text,
    passed, risk_score, latency_ms
)

# Get metrics
metrics = observability.metrics.get_metric_summary("check_count", hours=1)
alerts = observability.alerting.get_active_alerts()
log = observability.audit.get_compliance_report("2024-01-01", "2024-01-02")
```

---

## Backend Integration

### Adding a Custom Backend

```python
from guardrail_framework.core import GuardrailBackendInterface, GuardrailResult

class CustomBackend(GuardrailBackendInterface):
    def check_input(self, text: str, context=None) -> GuardrailResult:
        result = GuardrailResult()
        # Your implementation
        return result
    
    def check_output(self, text: str, context=None) -> GuardrailResult:
        # Implementation
        pass
    
    def validate_tool_call(self, tool_name: str, tool_args: Dict, context=None) -> GuardrailResult:
        # Implementation
        pass
    
    def apply_policy(self, policy: GuardrailPolicy) -> bool:
        # Implementation
        pass

# Register with framework
framework.register_backend("custom", CustomBackend(config))
```

### Swapping Backends at Runtime

```python
# No code changes needed - just update the policy
framework.update_policy(policy_id, {
    "backend": GuardrailBackend.LAKERA  # Swap from GuardrailsAI to Lakera
})

# Existing calls continue working unchanged
result = framework.check_input("text", policy_id)
```

---

## Policy Management

### Policy Templates

```python
from guardrail_framework.compiler import PolicyTemplates

# Pre-built templates
strict = PolicyTemplates.strict_security()          # Maximum security
privacy = PolicyTemplates.privacy_focused()        # Privacy emphasis
balanced = PolicyTemplates.balanced()               # Security + usability
agent = PolicyTemplates.agent_execution()          # Agent-specific
```

### Compile to Backend Formats

```python
from guardrail_framework.compiler import PolicyCompiler

compiler = PolicyCompiler()

# Compile to specific backend format
nemo_config = compiler.compile(policy, GuardrailBackend.NEMO)
# Result: {"backend": "nemo", "colang_policy": "..."}

guardrails_config = compiler.compile(policy, GuardrailBackend.GUARDRAILS_AI)
# Result: {"backend": "guardrails_ai", "guardrails_yaml": "..."}
```

### Export Policies

```python
# Export as JSON
json_str = framework.export_policy(policy_id, format="json")

# Export as YAML
yaml_str = framework.export_policy(policy_id, format="yaml")

# Save to file
with open("policy.json", "w") as f:
    f.write(json_str)
```

---

## A/B Testing

### Set Up A/B Test

```python
from guardrail_framework.core import ABTestConfig

test = ABTestConfig(
    name="Security vs Usability",
    control_policy_id=policy_id_1,
    experiment_policy_id=policy_id_2,
    traffic_split=0.5,  # 50/50 split
    duration_hours=24,
    metrics_to_track=["block_rate", "latency_ms", "user_satisfaction"]
)

test_id = framework.create_ab_test(test)
```

### Assign Traffic

```python
# Get policy for each request (random assignment)
policy_id = framework.get_policy_for_abtest(test_id)

# Run guardrail check
result = framework.check_input(text, policy_id)

# Record result with test context
observability.record_guardrail_check(
    policy_id, backend, input_text, output_text,
    passed, risk_score, latency_ms,
    test_id=test_id  # Track to A/B test
)
```

---

## Observability

### Metrics

```python
observability = ObservabilityStack()

# Get metric summary for last hour
summary = observability.metrics.get_metric_summary("latency_ms", hours=1)
# {"count": 1250, "min": 32.1, "max": 245.3, "avg": 48.2, "latest": 45.1}

# Get historical data
history = observability.metrics.get_metric_history("risk_score", hours=24)

# Record custom metric
observability.metrics.record_metric("custom_metric", value=42.0, 
                                  policy_id=policy_id, backend_name="nemo")
```

### Alerts

```python
# Set alert rule
observability.alerting.add_alert_rule(
    name="high_block_rate",
    metric="block_rate",
    threshold=0.3,
    window_minutes=5,
    severity=AlertSeverity.WARNING
)

# Check for triggered alerts
alerts = observability.alerting.check_alerts()

# Get active alerts
active = observability.alerting.get_active_alerts()

# Resolve an alert
observability.alerting.resolve_alert(alert_id)
```

### Audit Logging

```python
# Log policy change
observability.audit.log_policy_change(
    policy_id,
    action="updated",
    details={"sensitivity": "medium"}
)

# Log backend error
observability.audit.log_backend_error(
    backend="nemo",
    error="Connection timeout",
    context={"retry_count": 3}
)

# Get compliance report
report = observability.audit.get_compliance_report(
    start_date="2024-01-01T00:00:00",
    end_date="2024-01-31T23:59:59"
)
```

### Performance Monitoring

```python
monitor = observability.performance

# Record individual check
monitor.record_check(backend="nemo", latency_ms=45, passed=True, policy_id=policy_id)

# Get SLA compliance
sla = monitor.get_sla_compliance(backend="nemo", hours=24)
# {"p95_latency_ms": 98, "p99_latency_ms": 245, "sla_met": True}

# Get backend health
health = monitor.get_backend_health("nemo")
# {"backend": "nemo", "status": "healthy", "latency": {...}, "sla": {...}}
```

---

## Production Deployment

### Docker

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY guardrail_framework/ ./guardrail_framework/
COPY app.py .

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: guardrail-framework
spec:
  replicas: 3
  selector:
    matchLabels:
      app: guardrail-framework
  template:
    metadata:
      labels:
        app: guardrail-framework
    spec:
      containers:
      - name: framework
        image: guardrail-framework:latest
        ports:
        - containerPort: 8000
        env:
        - name: LOG_LEVEL
          value: "INFO"
        - name: METRICS_RETENTION_HOURS
          value: "24"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

### FastAPI Server

```python
from fastapi import FastAPI
from guardrail_framework.core import GuardrailFramework

app = FastAPI()
framework = GuardrailFramework()

@app.post("/check-input")
async def check_input(text: str, policy_id: str):
    result = framework.check_input(text, policy_id)
    return result.to_dict()

@app.post("/check-output")
async def check_output(text: str, policy_id: str):
    result = framework.check_output(text, policy_id)
    return result.to_dict()

@app.get("/metrics")
async def get_metrics():
    return framework.get_metrics()

@app.get("/policies")
async def list_policies():
    return {
        policy_id: policy.to_dict()
        for policy_id, policy in framework.policies.items()
    }
```

### Configuration Management

```yaml
# config.yaml
guardrail_framework:
  log_level: INFO
  metrics:
    retention_hours: 24
    collection_interval_seconds: 60
  
  backends:
    nemo:
      enabled: true
      config:
        model: "nemo-guardrails-v1"
        colang_version: "1.0"
    
    guardrails_ai:
      enabled: true
      config:
        validators:
          - toxic_check
          - pii_check
    
    presidio:
      enabled: true
      config:
        confidence_threshold: 0.5
  
  alerting:
    enabled: true
    rules:
      high_block_rate:
        metric: block_rate
        threshold: 0.3
        window_minutes: 5
  
  audit:
    enabled: true
    log_file: /var/log/guardrail-audit.log
```

---

## Best Practices

1. **Start with templates** - Use PolicyTemplates for common use cases
2. **Monitor everything** - Enable observability for all production guardrails
3. **Test before deploying** - Use A/B tests to validate policy changes
4. **Layer your guardrails** - Combine input, output, and tool validation
5. **Regular audits** - Review compliance reports weekly
6. **Gradual rollout** - Start with low traffic split in A/B tests
7. **Alert on anomalies** - Set up alerts for unusual patterns
8. **Document policies** - Add descriptions and tags for governance
9. **Version your policies** - Treat policies as infrastructure as code
10. **Backup configurations** - Export policies regularly

---

## Troubleshooting

### High Latency

```python
# Profile latency by backend
health = observability.performance.get_backend_health("nemo")
if health["status"] == "degraded":
    # Route to faster backend
    framework.update_policy(policy_id, {
        "backend": GuardrailBackend.LAKERA
    })
```

### False Positives

```python
# Lower sensitivity
framework.update_policy(policy_id, {
    "sensitivity": "medium"  # was "high"
})
```

### Missing Alerts

```python
# Check alert rule configuration
rules = observability.alerting.alert_rules
for name, rule in rules.items():
    print(f"{name}: threshold={rule['threshold']}")
```

---

## Support & Contributing

For issues, feature requests, or contributions, visit:
- **GitHub**: https://github.com/yourorg/guardrail-framework
- **Documentation**: https://docs.guardrailframework.io
- **Community**: https://discord.gg/guardrails
