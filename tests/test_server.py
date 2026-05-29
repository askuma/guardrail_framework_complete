import pytest
from fastapi.testclient import TestClient
from guardrail_framework.server import app
from guardrail_framework.core import ActionType

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "backends" in data

def test_ready_check():
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json()["ready"] == True

def test_policy_lifecycle():
    # Create policy
    create_payload = {
        "name": "API Test Policy",
        "description": "Created via API test",
        "backend": "guardrails_ai",
        "risk_categories": ["prompt_injection"],
        "sensitivity": "medium",
        "action_on_violation": "block"
    }
    response = client.post("/policies", json=create_payload)
    assert response.status_code == 201
    data = response.json()
    assert "policy_id" in data
    policy_id = data["policy_id"]

    # Get single policy
    get_res = client.get(f"/policies/{policy_id}")
    assert get_res.status_code == 200
    assert get_res.json()["name"] == "API Test Policy"
    assert get_res.json()["action_on_violation"] == "block"

    # List policies
    list_res = client.get("/policies")
    assert list_res.status_code == 200
    assert policy_id in list_res.json()

    # Update policy
    update_res = client.patch(f"/policies/{policy_id}", json={"sensitivity": "high"})
    assert update_res.status_code == 200
    
    get_updated = client.get(f"/policies/{policy_id}")
    assert get_updated.json()["sensitivity"] == "high"

    # Export policy
    export_res = client.get(f"/policies/{policy_id}/export?format=json")
    assert export_res.status_code == 200
    assert "policy" in export_res.json()

    # Delete policy
    del_res = client.delete(f"/policies/{policy_id}")
    assert del_res.status_code == 200
    
    # Verify deletion
    verify_del = client.get(f"/policies/{policy_id}")
    assert verify_del.status_code == 404

def test_templates():
    res_list = client.get("/policies/templates/list")
    assert res_list.status_code == 200
    assert len(res_list.json()["templates"]) > 0

    res_create = client.post("/policies/templates/balanced")
    assert res_create.status_code == 201
    assert "policy_id" in res_create.json()

def test_check_endpoints():
    # Set up policy
    create_res = client.post("/policies/templates/balanced")
    policy_id = create_res.json()["policy_id"]

    # Input check
    in_res = client.post("/check/input", json={"text": "hello", "policy_id": policy_id})
    assert in_res.status_code == 200
    assert in_res.json()["passed"] == True

    # Output check
    out_res = client.post("/check/output", json={"text": "hello", "policy_id": policy_id})
    assert out_res.status_code == 200
    assert out_res.json()["passed"] == True

    # Tool check
    tool_res = client.post("/check/tool", json={
        "policy_id": policy_id,
        "tool_name": "test_tool",
        "tool_args": {}
    })
    assert tool_res.status_code == 200
    assert tool_res.json()["passed"] == True

def test_ab_test_endpoints():
    p1 = client.post("/policies/templates/balanced").json()["policy_id"]
    p2 = client.post("/policies/templates/strict_security").json()["policy_id"]

    create_ab = client.post("/abtests", json={
        "name": "API AB Test",
        "control_policy_id": p1,
        "experiment_policy_id": p2,
        "traffic_split": 0.5
    })
    assert create_ab.status_code == 201
    test_id = create_ab.json()["test_id"]

    list_ab = client.get("/abtests")
    assert list_ab.status_code == 200
    assert test_id in list_ab.json()

    assign_ab = client.get(f"/abtests/{test_id}/assign")
    assert assign_ab.status_code == 200
    assert assign_ab.json()["assigned_policy_id"] in [p1, p2]

def test_observability_endpoints():
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    
    dashboard = client.get("/metrics/dashboard")
    assert dashboard.status_code == 200
    assert "metrics" in dashboard.json()
    assert "alerts" in dashboard.json()
    
    audit = client.get("/audit?limit=10")
    assert audit.status_code == 200
    assert "entries" in audit.json()

def test_schema_endpoints():
    assert client.get("/schema/backends").status_code == 200
    assert client.get("/schema/risk-categories").status_code == 200
    assert client.get("/schema/actions").status_code == 200
    
def test_edge_cases():
    # Invalid policy for check
    res = client.post("/check/input", json={"text": "test", "policy_id": "invalid"})
    assert res.status_code == 404
    
    # Invalid template
    res = client.post("/policies/templates/invalid")
    assert res.status_code == 404
    
    # Delete invalid policy
    res = client.delete("/policies/invalid")
    assert res.status_code == 404
