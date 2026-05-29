"""
Guardrail Framework Abstraction Layer
Unified interface for multiple guardrail backends (NeMo, GuardrailsAI, Presidio, Lakera, GA Guard)
"""

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from uuid import uuid4


class GuardrailBackend(str, Enum):
    """Supported guardrail backends"""
    NEMO = "nemo"
    GUARDRAILS_AI = "guardrails_ai"
    PRESIDIO = "presidio"
    LAKERA = "lakera"
    GA_GUARD = "ga_guard"
    CUSTOM = "custom"


class RiskCategory(str, Enum):
    """OWASP LLM Top 10 risk categories"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAKING = "jailbreaking"
    MALICIOUS_TOOL_USE = "malicious_tool_use"
    UNSAFE_CODE = "unsafe_code_generation"
    DATA_LEAKAGE = "data_leakage"
    DOS = "model_dos"
    INDIRECT_ATTACK = "indirect_attack"
    HALLUCINATION = "hallucination"
    MODEL_THEFT = "model_theft"
    SUPPLY_CHAIN = "supply_chain_poisoning"


class ActionType(str, Enum):
    """Guardrail action when violation detected"""
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    REWRITE = "rewrite"
    ESCALATE = "escalate"
    RATE_LIMIT = "rate_limit"


@dataclass
class GuardrailPolicy:
    """Unified policy definition across backends"""
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    version: str = "1.0"
    enabled: bool = True
    backend: GuardrailBackend = GuardrailBackend.GUARDRAILS_AI
    
    # Risk configuration
    risk_categories: List[RiskCategory] = field(default_factory=lambda: [RiskCategory.PROMPT_INJECTION])
    sensitivity: str = "medium"  # low, medium, high
    
    # Actions
    action_on_violation: ActionType = ActionType.BLOCK
    escalation_email: Optional[str] = None
    
    # Policy rules in unified format
    rules: Dict[str, Any] = field(default_factory=dict)
    
    # Backend-specific configs
    nemo_colang: Optional[str] = None
    guardrails_yaml: Optional[str] = None
    presidio_config: Optional[Dict[str, Any]] = None
    
    # Metadata
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    tags: List[str] = field(default_factory=list)


@dataclass
class GuardrailResult:
    """Unified result from guardrail check"""
    request_id: str = field(default_factory=lambda: str(uuid4()))
    passed: bool = True
    severity: str = "info"  # info, warning, critical
    
    # Risk detection
    detected_risks: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0  # 0-1 normalized score
    
    # Action taken
    action: ActionType = ActionType.ALLOW
    original_text: str = ""
    modified_text: str = ""
    
    # Metadata
    backend_used: GuardrailBackend = GuardrailBackend.CUSTOM
    latency_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Detailed findings
    findings: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ABTestConfig:
    """A/B testing configuration"""
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    enabled: bool = True
    
    control_policy_id: str = ""
    experiment_policy_id: str = ""
    
    traffic_split: float = 0.5  # 0-1, percentage to experiment group
    duration_hours: int = 24
    
    metrics_to_track: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class GuardrailBackendInterface(ABC):
    """Abstract interface all backends must implement"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def check_input(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        """Check input text before it reaches the model"""
        pass
    
    @abstractmethod
    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        """Check output text before sending to user"""
        pass
    
    @abstractmethod
    def validate_tool_call(self, tool_name: str, tool_args: Dict[str, Any], 
                          context: Optional[Dict] = None) -> GuardrailResult:
        """Validate agent tool calls before execution"""
        pass
    
    @abstractmethod
    def apply_policy(self, policy: GuardrailPolicy) -> bool:
        """Apply a policy to this backend"""
        pass


class NemoGuardrailsBackend(GuardrailBackendInterface):
    """NVIDIA NeMo Guardrails backend implementation"""
    
    def check_input(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.NEMO)
        start = time.time()
        
        # Simulate NeMo state machine check
        risk_score = self._calculate_risk_score(text)
        result.risk_score = risk_score
        result.passed = risk_score < 0.7
        
        if not result.passed:
            result.action = ActionType.BLOCK
            result.severity = "critical"
            result.detected_risks.append({
                "type": RiskCategory.PROMPT_INJECTION.value,
                "confidence": risk_score
            })
        
        result.latency_ms = (time.time() - start) * 1000
        return result
    
    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.NEMO)
        start = time.time()
        
        risk_score = self._calculate_risk_score(text)
        result.risk_score = risk_score
        result.passed = risk_score < 0.7
        result.original_text = text
        
        if not result.passed:
            result.action = ActionType.REDACT
            result.modified_text = self._redact_sensitive_info(text)
        else:
            result.modified_text = text
        
        result.latency_ms = (time.time() - start) * 1000
        return result
    
    def validate_tool_call(self, tool_name: str, tool_args: Dict[str, Any],
                          context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.NEMO)

        # Forbidden tools list — checked from both config and policy rules
        forbidden = set(self.config.get("restricted_tools", []) +
                        self.config.get("forbidden_tools", []))
        allowed   = set(self.config.get("allowed_tools", []))

        blocked = False
        if forbidden and tool_name in forbidden:
            blocked = True
        elif allowed and tool_name not in allowed:
            blocked = True

        if blocked:
            result.passed = False
            result.action = ActionType.BLOCK
            result.risk_score = 0.9
            result.severity = "critical"
            result.detected_risks.append({
                "type": RiskCategory.MALICIOUS_TOOL_USE.value,
                "tool": tool_name,
                "reason": "tool not in allowlist" if allowed else "tool in blocklist"
            })

        return result
    
    def apply_policy(self, policy: GuardrailPolicy) -> bool:
        if policy.nemo_colang:
            self.config["colang_policy"] = policy.nemo_colang
            return True
        return False
    
    def _calculate_risk_score(self, text: str) -> float:
        """Delegate to the shared WasmReadyScorer (single source of truth)."""
        from .opa_gaps import wasm_scorer
        sensitivity = self.config.get("sensitivity", "medium")
        score, _ = wasm_scorer.score(text, sensitivity)
        return score
    
    def _redact_sensitive_info(self, text: str) -> str:
        """Redact PII and sensitive information"""
        import re
        # Simple pattern matching - replace with Presidio in production
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]', text)  # SSN
        text = re.sub(r'\b\d{16}\b', '[CARD]', text)  # Card number
        return text


class GuardrailsAIBackend(GuardrailBackendInterface):
    """GuardrailsAI framework backend implementation"""
    
    def check_input(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.GUARDRAILS_AI)
        start = time.time()

        # Built-in validators always run
        base_score = self._score_text(text)

        # Additional validators from config
        validators = self.config.get("validators", [])
        extra = 0.0
        for validator in validators:
            if not self._run_validator(validator, text):
                result.detected_risks.append({"type": validator})
                extra += 0.25

        result.risk_score = min(base_score + extra, 1.0)
        result.passed = result.risk_score < 0.65

        if not result.passed:
            result.action = ActionType.BLOCK
            result.severity = "critical" if result.risk_score > 0.8 else "warning"

        result.latency_ms = (time.time() - start) * 1000
        return result
    
    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.GUARDRAILS_AI)
        start = time.time()
        
        result.original_text = text
        result.modified_text = text
        result.passed = True
        result.latency_ms = (time.time() - start) * 1000
        return result
    
    def validate_tool_call(self, tool_name: str, tool_args: Dict[str, Any], 
                          context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.GUARDRAILS_AI)
        result.passed = True
        return result
    
    def apply_policy(self, policy: GuardrailPolicy) -> bool:
        if policy.guardrails_yaml:
            self.config["policy_yaml"] = policy.guardrails_yaml
            return True
        return False
    
    def _score_text(self, text: str) -> float:
        """Delegate to the shared WasmReadyScorer."""
        from .opa_gaps import wasm_scorer
        sensitivity = self.config.get("sensitivity", "medium")
        score, _ = wasm_scorer.score(text, sensitivity)
        return score

    def _run_validator(self, validator: str, text: str) -> bool:
        """Run a named validator"""
        validators = {
            "toxic_check":        lambda t: "badword" not in t.lower(),
            "pii_check":          lambda t: "@" not in t,
            "hallucination_check": lambda t: len(t) > 0,
        }
        return validators.get(validator, lambda t: True)(text)


class PresidioBackend(GuardrailBackendInterface):
    """Microsoft Presidio PII detection backend"""
    
    def check_input(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.PRESIDIO)
        start = time.time()
        
        pii_entities = self._detect_pii(text)
        result.original_text = text
        
        if pii_entities:
            result.passed = False
            result.action = ActionType.REDACT
            result.modified_text = self._redact_pii(text, pii_entities)
            result.detected_risks = pii_entities
            result.risk_score = min(len(pii_entities) * 0.1, 1.0)
        else:
            result.passed = True
            result.modified_text = text
        
        result.latency_ms = (time.time() - start) * 1000
        return result
    
    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        return self.check_input(text, context)
    
    def validate_tool_call(self, tool_name: str, tool_args: Dict[str, Any], 
                          context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.PRESIDIO)
        result.passed = True
        return result
    
    def apply_policy(self, policy: GuardrailPolicy) -> bool:
        if policy.presidio_config:
            self.config.update(policy.presidio_config)
            return True
        return False
    
    def _detect_pii(self, text: str) -> List[Dict[str, Any]]:
        """Detect PII entities in text"""
        import re
        entities = []
        
        # Email pattern
        emails = re.finditer(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
        for email in emails:
            entities.append({
                "type": "EMAIL_ADDRESS",
                "text": email.group(),
                "start": email.start(),
                "end": email.end()
            })
        
        # Phone pattern
        phones = re.finditer(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', text)
        for phone in phones:
            entities.append({
                "type": "PHONE_NUMBER",
                "text": phone.group(),
                "start": phone.start(),
                "end": phone.end()
            })
        
        return entities
    
    def _redact_pii(self, text: str, entities: List[Dict[str, Any]]) -> str:
        """Redact PII from text"""
        for entity in sorted(entities, key=lambda e: e['end'], reverse=True):
            text = text[:entity['start']] + f"[{entity['type']}]" + text[entity['end']:]
        return text


class GuardrailFramework:
    """Main guardrail framework orchestrator"""
    
    def __init__(self):
        self.logger = logging.getLogger("GuardrailFramework")
        self.policies: Dict[str, GuardrailPolicy] = {}
        self.backends: Dict[str, GuardrailBackendInterface] = {}
        self.ab_tests: Dict[str, ABTestConfig] = {}
        self.audit_log: List[Dict[str, Any]] = []
        self.metrics: Dict[str, Any] = {}
        self._version_store: Optional[Any] = None   # set by server.py
        self._initialize_backends()
    
    def _initialize_backends(self):
        """Initialize default backends"""
        self.backends[GuardrailBackend.NEMO.value] = NemoGuardrailsBackend({})
        self.backends[GuardrailBackend.GUARDRAILS_AI.value] = GuardrailsAIBackend({})
        self.backends[GuardrailBackend.PRESIDIO.value] = PresidioBackend({})
    
    def register_backend(self, name: str, backend: GuardrailBackendInterface):
        """Register a custom backend"""
        self.backends[name] = backend
        self.logger.info(f"Backend registered: {name}")
    
    def create_policy(self, policy: GuardrailPolicy, created_by: str = "api") -> str:
        """Create and store a new policy."""
        self.policies[policy.id] = policy
        self.logger.info(f"Policy created: {policy.id} ({policy.name})")
        # version snapshot
        if hasattr(self, "_version_store") and self._version_store:
            self._version_store.save(policy, created_by=created_by, reason="created")
        # real-time push
        try:
            from .bundle import push_channel
            push_channel.broadcast({"type": "policy_created",
                                    "policy_id": policy.id,
                                    "policy_name": policy.name})
        except Exception:
            pass
        return policy.id
    
    def _inject_policy_rules(self, backend, policy):
        """Push policy.rules into backend config so validators can use them"""
        if policy.rules:
            backend.config.update(policy.rules)

    def check_input(self, text: str, policy_id: str, context: Optional[Dict] = None) -> GuardrailResult:
        """Check input against a policy (fail-closed / default-deny)."""
        from .testing import fail_closed_result
        from .opa_gaps import data_registry, status_reporter, prom_metrics
        if policy_id not in self.policies:
            return fail_closed_result(f"Policy not found: {policy_id}")

        policy  = self.policies[policy_id]
        backend = self.backends.get(policy.backend.value)
        if not backend:
            return fail_closed_result(f"Backend not configured: {policy.backend.value}")

        # Enrich context with external data providers
        enriched = data_registry.enrich(context or {})
        self._inject_policy_rules(backend, policy)
        try:
            result = backend.check_input(text, enriched)
        except Exception as exc:
            self.logger.error(f"Backend error in check_input: {exc}")
            result = fail_closed_result(str(exc))

        self._log_audit(policy_id, "input_check", text, result)
        status_reporter.record(policy_id, policy.backend.value, result.passed, result.latency_ms)
        prom_metrics.record_decision(policy_id, policy.backend.value,
                                     result.action.value, result.passed,
                                     result.latency_ms, result.risk_score)
        return result
    
    def check_output(self, text: str, policy_id: str, context: Optional[Dict] = None) -> GuardrailResult:
        """Check output against a policy (fail-closed / default-deny)."""
        from .testing import fail_closed_result
        from .opa_gaps import data_registry, status_reporter, prom_metrics
        if policy_id not in self.policies:
            return fail_closed_result(f"Policy not found: {policy_id}")

        policy  = self.policies[policy_id]
        backend = self.backends.get(policy.backend.value)
        if not backend:
            return fail_closed_result(f"Backend not configured: {policy.backend.value}")

        enriched = data_registry.enrich(context or {})
        self._inject_policy_rules(backend, policy)
        try:
            result = backend.check_output(text, enriched)
        except Exception as exc:
            self.logger.error(f"Backend error in check_output: {exc}")
            result = fail_closed_result(str(exc))

        self._log_audit(policy_id, "output_check", text, result)
        status_reporter.record(policy_id, policy.backend.value, result.passed, result.latency_ms)
        prom_metrics.record_decision(policy_id, policy.backend.value,
                                     result.action.value, result.passed,
                                     result.latency_ms, result.risk_score)
        return result
    
    def validate_tool_call(self, policy_id: str, tool_name: str,
                          tool_args: Dict[str, Any], context: Optional[Dict] = None) -> GuardrailResult:
        """Validate an agent tool call (fail-closed / default-deny)."""
        from .testing import fail_closed_result
        from .opa_gaps import data_registry, status_reporter, prom_metrics
        if policy_id not in self.policies:
            return fail_closed_result(f"Policy not found: {policy_id}")

        policy  = self.policies[policy_id]
        backend = self.backends.get(policy.backend.value)
        if not backend:
            return fail_closed_result(f"Backend not configured: {policy.backend.value}")

        enriched = data_registry.enrich(context or {})
        self._inject_policy_rules(backend, policy)
        try:
            result = backend.validate_tool_call(tool_name, tool_args, enriched)
        except Exception as exc:
            self.logger.error(f"Backend error in validate_tool_call: {exc}")
            result = fail_closed_result(str(exc))

        self._log_audit(policy_id, "tool_validation", tool_name, result)
        status_reporter.record(policy_id, policy.backend.value, result.passed, result.latency_ms)
        prom_metrics.record_decision(policy_id, policy.backend.value,
                                     result.action.value, result.passed,
                                     result.latency_ms, result.risk_score)
        return result
    
    def update_policy(self, policy_id: str, updates: Dict[str, Any],
                     updated_by: str = "api", reason: str = "") -> bool:
        """Update an existing policy (snapshots previous state first)."""
        if policy_id not in self.policies:
            return False

        policy = self.policies[policy_id]
        # snapshot before change
        if hasattr(self, "_version_store") and self._version_store:
            self._version_store.save(policy, created_by=updated_by, reason=f"pre-update: {reason}")

        for key, value in updates.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        policy.updated_at = datetime.utcnow().isoformat()
        self.logger.info(f"Policy updated: {policy_id}")

        # invalidate precompiler cache
        try:
            from .opa_gaps import precompiler
            if precompiler:
                precompiler.invalidate(policy_id)
        except Exception:
            pass
        # real-time push
        try:
            from .bundle import push_channel
            push_channel.broadcast({"type": "policy_updated",
                                    "policy_id": policy_id,
                                    "changes": list(updates.keys())})
        except Exception:
            pass
        return True
    
    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy and broadcast deletion event."""
        if policy_id in self.policies:
            del self.policies[policy_id]
            self.logger.info(f"Policy deleted: {policy_id}")
            try:
                from .bundle import push_channel
                push_channel.broadcast({"type": "policy_deleted", "policy_id": policy_id})
            except Exception:
                pass
            return True
        return False
    
    def create_ab_test(self, test_config: ABTestConfig) -> str:
        """Create an A/B test configuration"""
        self.ab_tests[test_config.id] = test_config
        self.logger.info(f"A/B test created: {test_config.id} ({test_config.name})")
        return test_config.id
    
    def get_policy_for_abtest(self, test_id: str) -> str:
        """Get policy ID based on A/B test assignment"""
        if test_id not in self.ab_tests:
            raise ValueError(f"A/B test not found: {test_id}")
        
        test = self.ab_tests[test_id]
        import random
        
        # Randomly assign to control or experiment
        if random.random() < test.traffic_split:
            return test.experiment_policy_id
        else:
            return test.control_policy_id
    
    def _log_audit(self, policy_id: str, action: str, input_text: str, result: GuardrailResult):
        """Log guardrail checks for audit trail"""
        self.audit_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "policy_id": policy_id,
            "action": action,
            "passed": result.passed,
            "severity": result.severity,
            "action_taken": result.action.value,
            "risk_score": result.risk_score,
            "latency_ms": result.latency_ms,
            "backend": result.backend_used.value,
            "request_id": result.request_id
        })
        
        # Update metrics
        self._update_metrics(result)
    
    def _update_metrics(self, result: GuardrailResult):
        """Update aggregated metrics"""
        if "total_checks" not in self.metrics:
            self.metrics = {
                "total_checks": 0,
                "passed": 0,
                "blocked": 0,
                "avg_latency_ms": 0,
                "by_backend": {},
                "by_action": {}
            }
        
        self.metrics["total_checks"] += 1
        if result.passed:
            self.metrics["passed"] += 1
        else:
            self.metrics["blocked"] += 1
        
        backend_name = result.backend_used.value
        if backend_name not in self.metrics["by_backend"]:
            self.metrics["by_backend"][backend_name] = 0
        self.metrics["by_backend"][backend_name] += 1
        
        action_name = result.action.value
        if action_name not in self.metrics["by_action"]:
            self.metrics["by_action"][action_name] = 0
        self.metrics["by_action"][action_name] += 1
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get aggregated metrics"""
        return self.metrics
    
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit log entries"""
        return self.audit_log[-limit:]
    
    def export_policy(self, policy_id: str, format: str = "json") -> str:
        """Export policy in specified format"""
        if policy_id not in self.policies:
            return ""
        
        policy = self.policies[policy_id]
        if format == "json":
            return json.dumps(asdict(policy), indent=2)
        elif format == "yaml":
            return self._convert_to_yaml(asdict(policy))
        
        return ""
    
    def _convert_to_yaml(self, data: Dict) -> str:
        """Convert policy to YAML format"""
        lines = []
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{key}:")
                for k, v in value.items():
                    lines.append(f"  {k}: {v}")
            elif isinstance(value, list):
                lines.append(f"{key}:")
                for item in value:
                    lines.append(f"  - {item}")
            else:
                lines.append(f"{key}: {value}")
        return "\n".join(lines)


# Global framework instance
_framework = None


def get_framework() -> GuardrailFramework:
    """Get or initialize the global framework"""
    global _framework
    if _framework is None:
        _framework = GuardrailFramework()
    return _framework
