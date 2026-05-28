# Guardrail Framework - Architecture & Deployment Guide

## System Architecture

```
┌───────────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                             │
│  ┌────────────┬──────────────┬──────────────┬──────────────┐     │
│  │   Chat    │   Agents     │   Search     │  RAG Pipeline│     │
│  │   Bots    │   (agentic)  │   Results    │   (retrieval)│     │
│  └─────┬──────┴──────┬───────┴──────┬───────┴──────┬───────┘     │
└────────┼─────────────┼──────────────┼──────────────┼─────────────┘
         │             │              │              │
    ┌────▼─────────────▼──────────────▼──────────────▼────┐
    │                                                     │
    │  GUARDRAIL FRAMEWORK ABSTRACTION LAYER            │
    │  ┌──────────────────────────────────────────────┐ │
    │  │  Policy Management & Routing                │ │
    │  │  - Create/update/delete policies             │ │
    │  │  - Route requests to appropriate backends   │ │
    │  │  - A/B test traffic splitting               │ │
    │  │  - Context-aware policy selection           │ │
    │  └──────────────────────────────────────────────┘ │
    │  ┌──────────────────────────────────────────────┐ │
    │  │  Unified Policy Language                    │ │
    │  │  - Single format for all backends            │ │
    │  │  - Automatic compilation to backend configs │ │
    │  │  - Policy versioning & migration             │ │
    │  └──────────────────────────────────────────────┘ │
    │                                                    │
    └────┬──────────┬──────────┬──────────┬─────────────┘
         │          │          │          │
    ┌────▼────┐ ┌──▼──────┐ ┌─▼────────┐ ┌▼─────────┐
    │  NEMO   │ │GUARDR   │ │PRESIDIO  │ │LAKERA   │
    │RAILS    │ │AILS AI  │ │(PII      │ │Guard    │
    │(State   │ │(Valid   │ │Redaction)│ │(Real-   │
    │Machine) │ │ators)   │ │          │ │time)    │
    └────┬────┘ └──┬──────┘ └─┬────────┘ └┬─────────┘
         │         │          │          │
         └─────────┴──────────┴──────────┘
                   │
    ┌──────────────▼───────────────────────┐
    │                                      │
    │  OBSERVABILITY STACK                │
    │  ┌──────────────────────────────┐   │
    │  │ Metrics Collector             │   │
    │  │ - Latency, throughput, errors │   │
    │  │ - Backend-specific metrics    │   │
    │  └──────────────────────────────┘   │
    │  ┌──────────────────────────────┐   │
    │  │ Alerting System               │   │
    │  │ - Real-time alert triggers    │   │
    │  │ - Custom alert rules          │   │
    │  └──────────────────────────────┘   │
    │  ┌──────────────────────────────┐   │
    │  │ Audit Logger                  │   │
    │  │ - Compliance trails           │   │
    │  │ - Policy change history       │   │
    │  └──────────────────────────────┘   │
    │  ┌──────────────────────────────┐   │
    │  │ Performance Monitor            │   │
    │  │ - SLA compliance tracking      │   │
    │  │ - Backend health status        │   │
    │  └──────────────────────────────┘   │
    │                                      │
    └──────────────────────────────────────┘
         │           │           │
    ┌────▼───┐  ┌────▼────┐  ┌──▼────┐
    │Metrics │  │Alerts   │  │Logs   │
    │DB      │  │Queue    │  │Store  │
    └────────┘  └─────────┘  └───────┘
```

## Deployment Patterns

### Pattern 1: Microservices Deployment

```yaml
# Kubernetes manifests
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: guardrail-config
data:
  config.yaml: |
    log_level: INFO
    backends:
      nemo:
        enabled: true
      guardrails_ai:
        enabled: true
      presidio:
        enabled: true

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: guardrail-api
  namespace: ai-safety
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: guardrail-api
      tier: backend
  template:
    metadata:
      labels:
        app: guardrail-api
        tier: backend
    spec:
      containers:
      - name: guardrail-api
        image: registry.internal/guardrail-framework:latest
        imagePullPolicy: IfNotPresent
        
        ports:
        - name: http
          containerPort: 8000
        - name: metrics
          containerPort: 8001
        
        env:
        - name: ENVIRONMENT
          value: production
        - name: LOG_LEVEL
          value: INFO
        - name: METRICS_ENABLED
          value: "true"
        
        volumeMounts:
        - name: config
          mountPath: /etc/guardrail
        - name: cache
          mountPath: /var/cache/guardrail
        
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
        
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
      
      volumes:
      - name: config
        configMap:
          name: guardrail-config
      - name: cache
        emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  name: guardrail-api
  namespace: ai-safety
spec:
  type: ClusterIP
  ports:
  - name: http
    port: 8000
    targetPort: 8000
  - name: metrics
    port: 8001
    targetPort: 8001
  selector:
    app: guardrail-api
    tier: backend

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: guardrail-api-hpa
  namespace: ai-safety
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: guardrail-api
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Pattern 2: Sidecar Container Deployment

```dockerfile
# Main application with guardrail sidecar
FROM python:3.9 as app

WORKDIR /app
COPY app.py requirements.txt ./
RUN pip install -r requirements.txt

EXPOSE 8000
CMD ["python", "app.py"]

---

# Guardrail sidecar
FROM python:3.9 as guardrail

WORKDIR /app
COPY guardrail_framework/ ./
COPY guardrail_server.py ./
RUN pip install guardrail-framework==1.0.0

EXPOSE 9000
CMD ["python", "guardrail_server.py"]
```

```yaml
# Pod with sidecar
apiVersion: v1
kind: Pod
metadata:
  name: app-with-guardrail
spec:
  containers:
  - name: app
    image: myapp:latest
    ports:
    - containerPort: 8000
    env:
    - name: GUARDRAIL_URL
      value: "http://localhost:9000"
  
  - name: guardrail-sidecar
    image: guardrail-framework:latest
    ports:
    - containerPort: 9000
```

### Pattern 3: Edge Deployment (CDN-based)

```python
# Minimal edge guardrail (Cloudflare Workers / Lambda@Edge)
async def guardrail_check(request):
    text = request.get("text")
    policy_id = request.get("policy_id")
    
    # Load minimal policy in edge location
    policy = EDGE_POLICIES[policy_id]
    
    # Run lightweight content filter
    if contains_forbidden_keywords(text, policy["blacklist"]):
        return {"passed": False, "action": "block"}
    
    # Pass to origin for full check
    return await call_origin_guardrail(text, policy_id)
```

## Integration Patterns

### Pattern 1: Middleware Integration

```python
# FastAPI middleware
from fastapi import FastAPI, Request

app = FastAPI()
framework = GuardrailFramework()

@app.middleware("http")
async def guardrail_middleware(request: Request, call_next):
    # Get policy from header or request context
    policy_id = request.headers.get("X-Guardrail-Policy", "default")
    
    # Extract body
    body = await request.body()
    
    # Run guardrail check
    result = framework.check_input(
        body.decode(),
        policy_id,
        context={"user_id": request.headers.get("X-User-ID")}
    )
    
    # Block if necessary
    if not result.passed and result.action == ActionType.BLOCK:
        return JSONResponse(
            status_code=403,
            content={"error": "Request blocked by guardrails"}
        )
    
    # Continue to next middleware
    response = await call_next(request)
    
    # Check response
    response_body = b""
    async for chunk in response.body_iterator:
        response_body += chunk
    
    output_result = framework.check_output(
        response_body.decode(),
        policy_id
    )
    
    if output_result.action == ActionType.REDACT:
        response_body = output_result.modified_text.encode()
    
    return StreamingResponse(
        iter([response_body]),
        status_code=response.status_code,
        headers=dict(response.headers)
    )
```

### Pattern 2: Agent Tool Wrapper

```python
# Wrap agent tools with guardrail validation
from typing import Callable

def guardrail_tool(tool: Callable, policy_id: str, framework: GuardrailFramework):
    async def wrapper(*args, **kwargs):
        # Validate tool call
        result = framework.validate_tool_call(
            policy_id=policy_id,
            tool_name=tool.__name__,
            tool_args={**kwargs},
            context={"args_count": len(args)}
        )
        
        if not result.passed:
            raise PermissionError(f"Tool call blocked: {result.detected_risks}")
        
        # Execute tool
        return await tool(*args, **kwargs)
    
    return wrapper

# Usage
@guardrail_tool(tool=delete_file, policy_id="agent_policy", framework=framework)
async def safe_delete_file(path: str):
    # Implementation
    pass
```

### Pattern 3: RAG Pipeline Integration

```python
# Protect RAG pipeline with guardrails
async def guardrail_protected_rag(query: str, policy_id: str):
    framework = get_framework()
    
    # 1. Check user query
    input_result = framework.check_input(query, policy_id)
    if not input_result.passed:
        return {"error": "Query blocked by guardrails"}
    
    # 2. Retrieve documents
    documents = await retriever.retrieve(query)
    
    # 3. Check retrieved context for indirect injection
    for doc in documents:
        context_result = framework.check_input(
            doc.content,
            policy_id,
            context={"source": "retrieval", "doc_id": doc.id}
        )
        if not context_result.passed:
            # Mark as suspicious but include with metadata
            doc.metadata["guardrail_warning"] = context_result.detected_risks
    
    # 4. Generate response
    response = await llm.generate(query, documents)
    
    # 5. Check output
    output_result = framework.check_output(response, policy_id)
    
    if output_result.action == ActionType.REDACT:
        response = output_result.modified_text
    
    return {
        "response": response,
        "guardrail_checks": {
            "input": input_result.passed,
            "context": len([d for d in documents if d.metadata.get("guardrail_warning")]),
            "output": output_result.passed
        }
    }
```

## Performance Optimization

### Caching Strategy

```python
# Cache policy compilations
from functools import lru_cache

class CachedPolicyCompiler(PolicyCompiler):
    @lru_cache(maxsize=1000)
    def compile(self, policy_id: str, backend: GuardrailBackend):
        # Compile and cache
        policy = POLICY_STORE[policy_id]
        return super().compile(policy, backend)
    
    def invalidate_cache(self, policy_id: str):
        self.compile.cache_clear()
```

### Batch Processing

```python
# Batch guardrail checks for throughput
async def batch_check_inputs(texts: List[str], policy_id: str):
    framework = get_framework()
    
    # Parallel checks
    import asyncio
    tasks = [
        framework.check_input(text, policy_id)
        for text in texts
    ]
    
    results = await asyncio.gather(*tasks)
    return results
```

### Distributed Tracing

```python
# Add tracing for observability
from opentelemetry import trace
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

tracer = trace.get_tracer(__name__)

def check_input_traced(text: str, policy_id: str):
    with tracer.start_as_current_span("guardrail_check_input") as span:
        span.set_attribute("policy_id", policy_id)
        span.set_attribute("text_length", len(text))
        
        result = framework.check_input(text, policy_id)
        
        span.set_attribute("passed", result.passed)
        span.set_attribute("latency_ms", result.latency_ms)
        
        return result
```

## Scaling Considerations

### Horizontal Scaling

- Deploy multiple guardrail instances behind load balancer
- Use shared metric/audit backends (Redis, PostgreSQL)
- Cache compiled policies to reduce compilation overhead
- Monitor per-instance metrics for uneven load

### Vertical Scaling

- Increase instance memory for larger policy caches
- Use faster hardware for lower latency backends
- Pre-compile frequently-used policies at startup
- Use async/parallel processing for batch checks

### Storage

- Metrics: Time-series DB (InfluxDB, Prometheus)
- Audit logs: Long-term storage (S3, BigQuery)
- Policies: Config management system (Consul, etcd)
- Cache: In-memory (Redis) or local (memcached)

## Monitoring & Alerting

```python
# Example monitoring stack integration
from prometheus_client import Counter, Histogram, Gauge

# Define metrics
guardrail_checks = Counter(
    'guardrail_checks_total',
    'Total guardrail checks',
    ['policy_id', 'backend', 'passed']
)

guardrail_latency = Histogram(
    'guardrail_latency_ms',
    'Guardrail check latency',
    ['policy_id', 'backend'],
    buckets=[10, 50, 100, 500, 1000, 5000]
)

guardrail_risk_score = Gauge(
    'guardrail_risk_score',
    'Average risk score',
    ['policy_id', 'backend']
)

# Record metrics
result = framework.check_input(text, policy_id)
guardrail_checks.labels(
    policy_id=policy_id,
    backend=result.backend_used.value,
    passed=result.passed
).inc()

guardrail_latency.labels(
    policy_id=policy_id,
    backend=result.backend_used.value
).observe(result.latency_ms)
```

## Troubleshooting Guide

### Issue: High False Positive Rate

1. Lower sensitivity: `"sensitivity": "medium"`
2. Refine rules: Update risk_categories
3. A/B test new policy before rolling out
4. Review blocked examples to find patterns

### Issue: Latency Exceeding SLA

1. Switch to faster backend: Lakera Guard
2. Enable caching for compiled policies
3. Use async batch processing
4. Scale horizontally

### Issue: Inconsistent Results Across Backends

1. Ensure all backends use same risk category definitions
2. Compile policy through PolicyCompiler
3. Test policy on sample data first
4. Check backend-specific configurations

---

This comprehensive system provides production-grade AI safety guardrails with maximum flexibility and observability.
