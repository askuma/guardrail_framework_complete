"""
Guardrail Framework - FastAPI Server
REST API for the Guardrail Framework Abstraction Layer
"""

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardrail_framework.core import (
    GuardrailFramework, GuardrailPolicy, GuardrailBackend,
    RiskCategory, ActionType, ABTestConfig, get_framework
)
from guardrail_framework.compiler import UnifiedPolicyBuilder, PolicyTemplates, PolicyCompiler
from guardrail_framework.observability import ObservabilityStack

# ─── App Setup ────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("guardrail_server")

app = FastAPI(
    title="Guardrail Framework API",
    description="Unified guardrail abstraction layer for NeMo, GuardrailsAI, Presidio and more",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

framework: GuardrailFramework = get_framework()
observability = ObservabilityStack()
compiler = PolicyCompiler()

# ─── Request / Response Models ────────────────────────────────────────────────

class CheckInputRequest(BaseModel):
    text: str
    policy_id: str
    context: Optional[Dict[str, Any]] = None

class CheckOutputRequest(BaseModel):
    text: str
    policy_id: str
    context: Optional[Dict[str, Any]] = None

class ValidateToolRequest(BaseModel):
    policy_id: str
    tool_name: str
    tool_args: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None

class CreatePolicyRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    backend: str = "guardrails_ai"
    risk_categories: List[str] = ["prompt_injection"]
    sensitivity: str = "medium"
    action_on_violation: str = "block"
    escalation_email: Optional[str] = None
    rules: Optional[Dict[str, Any]] = {}
    tags: Optional[List[str]] = []

class UpdatePolicyRequest(BaseModel):
    sensitivity: Optional[str] = None
    action_on_violation: Optional[str] = None
    enabled: Optional[bool] = None
    rules: Optional[Dict[str, Any]] = None

class CreateABTestRequest(BaseModel):
    name: str
    control_policy_id: str
    experiment_policy_id: str
    traffic_split: float = 0.5
    duration_hours: int = 24
    metrics_to_track: Optional[List[str]] = []

# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health():
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
        "backends": list(framework.backends.keys()),
        "policies_loaded": len(framework.policies),
    }

@app.get("/ready", tags=["System"])
def ready():
    return {"ready": True}

# ─── Guardrail Checks ─────────────────────────────────────────────────────────

@app.post("/check/input", tags=["Guardrail Checks"])
def check_input(req: CheckInputRequest):
    """Check input text before it reaches the model."""
    if req.policy_id not in framework.policies:
        raise HTTPException(status_code=404, detail=f"Policy not found: {req.policy_id}")
    try:
        result = framework.check_input(req.text, req.policy_id, req.context)
        policy = framework.policies[req.policy_id]
        observability.record_guardrail_check(
            req.policy_id, policy.backend.value,
            req.text, result.modified_text or req.text,
            result.passed, result.risk_score, result.latency_ms
        )
        return {
            "request_id": result.request_id,
            "passed": result.passed,
            "risk_score": result.risk_score,
            "severity": result.severity,
            "action": result.action.value,
            "detected_risks": result.detected_risks,
            "modified_text": result.modified_text,
            "backend_used": result.backend_used.value,
            "latency_ms": result.latency_ms,
            "timestamp": result.timestamp,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/check/output", tags=["Guardrail Checks"])
def check_output(req: CheckOutputRequest):
    """Check output text before it is returned to the user."""
    if req.policy_id not in framework.policies:
        raise HTTPException(status_code=404, detail=f"Policy not found: {req.policy_id}")
    try:
        result = framework.check_output(req.text, req.policy_id, req.context)
        return {
            "request_id": result.request_id,
            "passed": result.passed,
            "risk_score": result.risk_score,
            "action": result.action.value,
            "original_text": result.original_text,
            "modified_text": result.modified_text,
            "detected_risks": result.detected_risks,
            "latency_ms": result.latency_ms,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/check/tool", tags=["Guardrail Checks"])
def validate_tool(req: ValidateToolRequest):
    """Validate an agent tool call before execution."""
    if req.policy_id not in framework.policies:
        raise HTTPException(status_code=404, detail=f"Policy not found: {req.policy_id}")
    try:
        result = framework.validate_tool_call(
            req.policy_id, req.tool_name, req.tool_args, req.context
        )
        return {
            "passed": result.passed,
            "action": result.action.value,
            "detected_risks": result.detected_risks,
            "latency_ms": result.latency_ms,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ─── Policies ─────────────────────────────────────────────────────────────────

@app.get("/policies", tags=["Policies"])
def list_policies():
    """List all registered policies."""
    return {
        pid: {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "backend": p.backend.value,
            "sensitivity": p.sensitivity,
            "action_on_violation": p.action_on_violation.value,
            "enabled": p.enabled,
            "tags": p.tags,
            "created_at": p.created_at,
            "updated_at": p.updated_at,
        }
        for pid, p in framework.policies.items()
    }


@app.get("/policies/{policy_id}", tags=["Policies"])
def get_policy(policy_id: str):
    """Get a single policy by ID."""
    if policy_id not in framework.policies:
        raise HTTPException(status_code=404, detail=f"Policy not found: {policy_id}")
    p = framework.policies[policy_id]
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "backend": p.backend.value,
        "risk_categories": [r.value for r in p.risk_categories],
        "sensitivity": p.sensitivity,
        "action_on_violation": p.action_on_violation.value,
        "enabled": p.enabled,
        "rules": p.rules,
        "tags": p.tags,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
    }


@app.post("/policies", tags=["Policies"], status_code=201)
def create_policy(req: CreatePolicyRequest):
    """Create a new guardrail policy."""
    try:
        risk_cats = [RiskCategory(r) for r in req.risk_categories]
        backend   = GuardrailBackend(req.backend)
        action    = ActionType(req.action_on_violation)

        policy = UnifiedPolicyBuilder() \
            .with_name(req.name) \
            .with_description(req.description) \
            .with_backend(backend) \
            .with_risk_categories(risk_cats) \
            .with_sensitivity(req.sensitivity) \
            .with_action(action) \
            .with_rules(req.rules or {}) \
            .build()

        if req.escalation_email:
            policy.escalation_email = req.escalation_email
        for tag in (req.tags or []):
            policy.tags.append(tag)

        policy_id = framework.create_policy(policy)
        return {"policy_id": policy_id, "message": "Policy created successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.patch("/policies/{policy_id}", tags=["Policies"])
def update_policy(policy_id: str, req: UpdatePolicyRequest):
    """Update an existing policy."""
    if policy_id not in framework.policies:
        raise HTTPException(status_code=404, detail=f"Policy not found: {policy_id}")
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    if "action_on_violation" in updates:
        updates["action_on_violation"] = ActionType(updates["action_on_violation"])
    framework.update_policy(policy_id, updates)
    return {"message": "Policy updated", "policy_id": policy_id}


@app.delete("/policies/{policy_id}", tags=["Policies"])
def delete_policy(policy_id: str):
    """Delete a policy."""
    if not framework.delete_policy(policy_id):
        raise HTTPException(status_code=404, detail=f"Policy not found: {policy_id}")
    return {"message": "Policy deleted", "policy_id": policy_id}


@app.get("/policies/{policy_id}/export", tags=["Policies"])
def export_policy(policy_id: str, format: str = "json"):
    """Export a policy as JSON or YAML."""
    if policy_id not in framework.policies:
        raise HTTPException(status_code=404, detail=f"Policy not found: {policy_id}")
    exported = framework.export_policy(policy_id, format=format)
    return {"format": format, "policy": exported}


@app.get("/policies/templates/list", tags=["Policies"])
def list_templates():
    """List available policy templates."""
    return {
        "templates": [
            {"name": "strict_security",  "description": "Maximum security — blocks all suspicious activity"},
            {"name": "privacy_focused",  "description": "Emphasises PII redaction"},
            {"name": "balanced",         "description": "Balanced security and usability"},
            {"name": "agent_execution",  "description": "Tool validation for autonomous agents"},
        ]
    }


@app.post("/policies/templates/{template_name}", tags=["Policies"], status_code=201)
def create_from_template(template_name: str):
    """Create a policy from a pre-built template."""
    templates = {
        "strict_security": PolicyTemplates.strict_security,
        "privacy_focused": PolicyTemplates.privacy_focused,
        "balanced":        PolicyTemplates.balanced,
        "agent_execution": PolicyTemplates.agent_execution,
    }
    if template_name not in templates:
        raise HTTPException(status_code=404, detail=f"Template not found: {template_name}")
    policy = templates[template_name]()
    policy_id = framework.create_policy(policy)
    return {"policy_id": policy_id, "template": template_name, "message": "Policy created from template"}

# ─── A/B Tests ────────────────────────────────────────────────────────────────

@app.get("/abtests", tags=["A/B Tests"])
def list_abtests():
    """List all A/B tests."""
    return {
        tid: {
            "id": t.id,
            "name": t.name,
            "control_policy_id": t.control_policy_id,
            "experiment_policy_id": t.experiment_policy_id,
            "traffic_split": t.traffic_split,
            "duration_hours": t.duration_hours,
            "enabled": t.enabled,
            "created_at": t.created_at,
        }
        for tid, t in framework.ab_tests.items()
    }


@app.post("/abtests", tags=["A/B Tests"], status_code=201)
def create_abtest(req: CreateABTestRequest):
    """Create an A/B test between two policies."""
    for pid in [req.control_policy_id, req.experiment_policy_id]:
        if pid not in framework.policies:
            raise HTTPException(status_code=404, detail=f"Policy not found: {pid}")
    test = ABTestConfig(
        name=req.name,
        control_policy_id=req.control_policy_id,
        experiment_policy_id=req.experiment_policy_id,
        traffic_split=req.traffic_split,
        duration_hours=req.duration_hours,
        metrics_to_track=req.metrics_to_track or [],
    )
    test_id = framework.create_ab_test(test)
    return {"test_id": test_id, "message": "A/B test created"}


@app.get("/abtests/{test_id}/assign", tags=["A/B Tests"])
def assign_abtest(test_id: str):
    """Get a policy assignment for a given A/B test (random split)."""
    if test_id not in framework.ab_tests:
        raise HTTPException(status_code=404, detail=f"A/B test not found: {test_id}")
    policy_id = framework.get_policy_for_abtest(test_id)
    policy    = framework.policies[policy_id]
    return {
        "test_id": test_id,
        "assigned_policy_id": policy_id,
        "policy_name": policy.name,
    }

# ─── Observability ────────────────────────────────────────────────────────────

@app.get("/metrics", tags=["Observability"])
def get_metrics():
    """Get aggregated metrics."""
    return framework.get_metrics()


@app.get("/metrics/dashboard", tags=["Observability"])
def get_dashboard():
    """Get full dashboard data (metrics + alerts)."""
    return observability.get_dashboard_data()


@app.get("/audit", tags=["Observability"])
def get_audit_log(limit: int = 100):
    """Get recent audit log entries."""
    return {"entries": framework.get_audit_log(limit=limit)}


@app.get("/alerts", tags=["Observability"])
def get_alerts():
    """Get active alerts."""
    alerts = observability.alerting.get_active_alerts()
    return {
        "active_alerts": [
            {
                "id": a.id,
                "type": a.alert_type.value,
                "severity": a.severity.value,
                "title": a.title,
                "description": a.description,
                "metric_value": a.metric_value,
                "threshold": a.threshold,
                "timestamp": a.timestamp,
            }
            for a in alerts
        ]
    }


@app.delete("/alerts/{alert_id}", tags=["Observability"])
def resolve_alert(alert_id: str):
    """Resolve an alert."""
    observability.alerting.resolve_alert(alert_id)
    return {"message": "Alert resolved", "alert_id": alert_id}


# ─── Enums reference ──────────────────────────────────────────────────────────

@app.get("/schema/backends", tags=["Schema"])
def list_backends():
    return {"backends": [b.value for b in GuardrailBackend]}

@app.get("/schema/risk-categories", tags=["Schema"])
def list_risk_categories():
    return {"risk_categories": [r.value for r in RiskCategory]}

@app.get("/schema/actions", tags=["Schema"])
def list_actions():
    return {"actions": [a.value for a in ActionType]}


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
