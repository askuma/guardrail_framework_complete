import pytest
from guardrail_framework.core import (
    GuardrailFramework, GuardrailPolicy, RiskCategory, 
    ActionType, ABTestConfig, GuardrailBackend
)
from guardrail_framework.compiler import UnifiedPolicyBuilder

def test_framework_initialization():
    framework = GuardrailFramework()
    assert len(framework.policies) == 0
    assert len(framework.ab_tests) == 0

def test_create_get_delete_policy():
    framework = GuardrailFramework()
    policy = UnifiedPolicyBuilder() \
        .with_name("Test Policy") \
        .with_backend(GuardrailBackend.GUARDRAILS_AI) \
        .with_risk_categories([RiskCategory.DATA_LEAKAGE]) \
        .with_action(ActionType.BLOCK) \
        .build()

    policy_id = framework.create_policy(policy)
    assert policy_id in framework.policies

    retrieved = framework.policies.get(policy_id)
    assert retrieved.name == "Test Policy"
    assert retrieved.action_on_violation == ActionType.BLOCK

    assert framework.delete_policy(policy_id) == True
    assert policy_id not in framework.policies
    
    # Edge case: Delete non-existent
    assert framework.delete_policy("nonexistent") == False
    
    # Edge case: Get non-existent
    assert framework.policies.get("nonexistent") is None

def test_update_policy():
    framework = GuardrailFramework()
    policy = UnifiedPolicyBuilder().with_name("Update Me").build()
    policy_id = framework.create_policy(policy)

    framework.update_policy(policy_id, {"sensitivity": "high", "action_on_violation": ActionType.REDACT})
    updated = framework.policies.get(policy_id)
    
    assert updated.sensitivity == "high"
    assert updated.action_on_violation == ActionType.REDACT
    
    # Edge case: update non-existent policy
    res = framework.update_policy("nonexistent", {"sensitivity": "low"})
    assert res == False

def test_ab_test_creation_and_routing():
    framework = GuardrailFramework()
    p1 = framework.create_policy(UnifiedPolicyBuilder().with_name("P1").build())
    p2 = framework.create_policy(UnifiedPolicyBuilder().with_name("P2").build())

    ab_config = ABTestConfig(
        name="Test 1",
        control_policy_id=p1,
        experiment_policy_id=p2,
        traffic_split=0.5
    )
    test_id = framework.create_ab_test(ab_config)
    assert test_id in framework.ab_tests

    # Mock random to test routing predictability
    import random
    original_random = random.random
    try:
        random.random = lambda: 0.1 # < 0.5, should return experiment
        routed_id = framework.get_policy_for_abtest(test_id)
        assert routed_id == p2
        
        random.random = lambda: 0.9 # >= 0.5, should return control
        routed_id = framework.get_policy_for_abtest(test_id)
        assert routed_id == p1
    finally:
        random.random = original_random
        
    # Edge case: non-existent AB test
    try:
        framework.get_policy_for_abtest("invalid_id")
        assert False, "Should raise ValueError"
    except ValueError:
        pass

def test_tool_validation_logic():
    framework = GuardrailFramework()
    policy = UnifiedPolicyBuilder() \
        .with_name("Agent Policy") \
        .with_backend(GuardrailBackend.NEMO) \
        .with_rules({
            "allowed_tools": ["safe_tool"],
            "forbidden_tools": ["danger_tool"]
        }) \
        .build()
    policy_id = framework.create_policy(policy)

    # Allowed tool
    res = framework.validate_tool_call(policy_id, "safe_tool", {})
    assert res.passed == True

    # Forbidden tool
    res = framework.validate_tool_call(policy_id, "danger_tool", {})
    assert res.passed == False
    assert res.action == ActionType.BLOCK
    assert res.detected_risks[0]["type"] == RiskCategory.MALICIOUS_TOOL_USE.value
    
    # Neutral tool (not allowed or forbidden explicitly, but allowed list exists)
    res = framework.validate_tool_call(policy_id, "other_tool", {})
    assert res.passed == False
    
    # No rules tool validation but allowlist must contain the tool or have empty blocklist behavior.
    # The NeMo implementation blocks if allowed is non-empty and not found. 
    # If no rules are set, what happens? Let's check without rules.
    empty_policy = framework.create_policy(UnifiedPolicyBuilder().with_name("Empty").with_backend(GuardrailBackend.GUARDRAILS_AI).build())
    res = framework.validate_tool_call(empty_policy, "any_tool", {})
    assert res.passed == True

def test_export_import():
    framework = GuardrailFramework()
    policy = UnifiedPolicyBuilder().with_name("Export Policy").build()
    pid = framework.create_policy(policy)
    
    json_str = framework.export_policy(pid, format="json")
    assert "Export Policy" in json_str
    
    yaml_str = framework.export_policy(pid, format="yaml")
    assert "name: Export Policy" in yaml_str
    
    xml_str = framework.export_policy(pid, format="xml")
    assert xml_str == ""

def test_check_input_output():
    framework = GuardrailFramework()
    policy = UnifiedPolicyBuilder().with_name("Check").build()
    pid = framework.create_policy(policy)
    
    res = framework.check_input("hello", pid)
    assert res.passed
    assert res.risk_score == 0.0
    
    res = framework.check_output("hello", pid)
    assert res.passed
    assert res.risk_score == 0.0
