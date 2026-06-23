import pytest
import json
from guardrail_framework.core import (
    GuardrailPolicy, RiskCategory, ActionType, GuardrailBackend
)
from guardrail_framework.compiler import PolicyCompiler, UnifiedPolicyBuilder, PolicyTemplates

def test_builder_chaining_and_validation():
    builder = UnifiedPolicyBuilder()
    
    # Should raise error without name
    with pytest.raises(ValueError, match="Policy name is required"):
        builder.build()
        
    policy = builder \
        .with_name("My Policy") \
        .with_description("Desc") \
        .with_backend(GuardrailBackend.NEMO) \
        .with_risk_categories([RiskCategory.DATA_LEAKAGE]) \
        .with_sensitivity("high") \
        .with_action(ActionType.BLOCK) \
        .with_escalation_email("admin@test.com") \
        .with_rules({"max_len": 100}) \
        .with_tag("test_tag") \
        .build()
        
    assert policy.name == "My Policy"
    assert policy.description == "Desc"
    assert policy.backend == GuardrailBackend.NEMO
    assert RiskCategory.DATA_LEAKAGE in policy.risk_categories
    assert policy.sensitivity == "high"
    assert policy.action_on_violation == ActionType.BLOCK
    assert policy.escalation_email == "admin@test.com"
    assert policy.rules["max_len"] == 100
    assert "test_tag" in policy.tags
    
    # Invalid sensitivity
    with pytest.raises(ValueError):
        UnifiedPolicyBuilder().with_sensitivity("extreme")

def test_compile_nemo():
    compiler = PolicyCompiler()
    policy = UnifiedPolicyBuilder() \
        .with_name("Test NeMo") \
        .with_backend(GuardrailBackend.NEMO) \
        .with_risk_categories([RiskCategory.PROMPT_INJECTION]) \
        .build()
        
    res = compiler.compile(policy)
    assert res["backend"] == "nemo"
    
    colang = json.loads(res["colang_policy"])
    assert colang["version"] == "1.0"
    
    flows = colang["flows"]
    assert len(flows) == 1
    assert flows[0]["flow"]["name"] == "check_prompt_injection"
    
    steps = flows[0]["flow"]["steps"]
    assert "$risk_detected = detect_prompt_injection($input_text)" in steps

def test_compile_guardrails_ai():
    compiler = PolicyCompiler()
    policy = UnifiedPolicyBuilder() \
        .with_name("Test GAI") \
        .with_backend(GuardrailBackend.GUARDRAILS_AI) \
        .with_risk_categories([RiskCategory.DATA_LEAKAGE]) \
        .with_action(ActionType.REDACT) \
        .build()
        
    res = compiler.compile(policy)
    assert res["backend"] == "guardrails_ai"
    yaml_str = res["guardrails_yaml"]
    assert "type: pii_validator" in yaml_str
    assert "on_fail: redact" in yaml_str
    
def test_compile_presidio():
    compiler = PolicyCompiler()
    policy = UnifiedPolicyBuilder() \
        .with_name("Test Presidio") \
        .with_backend(GuardrailBackend.PRESIDIO) \
        .with_sensitivity("high") \
        .build()
        
    res = compiler.compile(policy)
    assert res["backend"] == "presidio"
    conf = res["presidio_config"]
    assert conf["pii_detection"]["confidence_threshold"] == 0.8
    assert "CREDIT_CARD" in conf["pii_detection"]["entities"]
    
def test_custom_backend_generic_compile():
    compiler = PolicyCompiler()
    policy = UnifiedPolicyBuilder() \
        .with_name("Test Custom") \
        .with_backend(GuardrailBackend.CUSTOM) \
        .build()

    result = compiler.compile(policy)
    assert result["backend"] == "custom"
    assert result["name"] == "Test Custom"

def test_policy_templates():
    strict = PolicyTemplates.strict_security()
    assert strict.name == "Strict Security"
    assert strict.backend == GuardrailBackend.GUARDRAILS_AI
    assert strict.action_on_violation == ActionType.BLOCK
    
    privacy = PolicyTemplates.privacy_focused()
    assert privacy.name == "Privacy Focused"
    assert privacy.backend == GuardrailBackend.PRESIDIO
    assert privacy.action_on_violation == ActionType.REDACT
    
    agent = PolicyTemplates.agent_execution()
    assert agent.backend == GuardrailBackend.NEMO
    assert "max_tool_calls_per_minute" in agent.rules
