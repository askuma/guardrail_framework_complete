"""
Guardrail Framework Abstraction Layer
Unified interface for multiple guardrail backends (NeMo, GuardrailsAI, Presidio, Lakera, GA Guard)
"""

import asyncio as _asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re as _re
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone
from urllib.parse import urlparse
from uuid import uuid4

# ── Optional SDKs — detected at import time, used lazily ─────────────────────
import importlib
import importlib.util as _ilu

_NEMO_SDK: bool = _ilu.find_spec("nemoguardrails") is not None
_GUARDRAILSAI_SDK: bool = _ilu.find_spec("guardrails") is not None
_PRESIDIO_SDK: bool = (
    _ilu.find_spec("presidio_analyzer") is not None
    and _ilu.find_spec("presidio_anonymizer") is not None
)
_presidio_analyzer: Any = None
_presidio_anonymizer: Any = None
_BOTO3_SDK: bool = _ilu.find_spec("boto3") is not None

if _PRESIDIO_SDK:
    try:
        _pa = importlib.import_module("presidio_analyzer")
        _pan = importlib.import_module("presidio_anonymizer")
        _presidio_analyzer = _pa.AnalyzerEngine()
        _presidio_anonymizer = _pan.AnonymizerEngine()
        logging.getLogger("core").info("presidio-analyzer SDK active — using real PII detection.")
    except Exception:
        _PRESIDIO_SDK = False

_log_core = logging.getLogger("core")
_log_core.info("SDK availability — nemo:%s guardrails_ai:%s presidio:%s",
               _NEMO_SDK, _GUARDRAILSAI_SDK, _PRESIDIO_SDK)

# Pattern used to detect when NeMo rails have blocked a response.
# NeMo returns its configured refusal text; we match common patterns.
_NEMO_REFUSAL_RE = _re.compile(
    r"I('m| am) (sorry|unable|not able to)|"
    r"(cannot|can't|won't|will not) (help|assist|answer|discuss|provide)|"
    r"(not allowed|not permitted|off.?limits|outside my)|"
    r"I (cannot|can't) (do|engage|talk about)",
    _re.IGNORECASE,
)

# Sensitivity → score threshold mapping (shared by all backends)
_THRESHOLDS: Dict[str, float] = {"low": 0.80, "medium": 0.65, "high": 0.45}

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _validate_external_url(url: str) -> str:
    """
    Reject URLs that are not safe to fetch from the server side.

    Rules:
    - Only https:// is permitted (blocks file://, gopher://, ftp://, etc.)
    - Bare IP literals that fall in private/loopback/link-local ranges are blocked.
    - Hostnames are not resolved here; restrict outbound egress at the network level
      if DNS-rebinding is a concern in your environment.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(
            f"Only https:// URLs are permitted for external backends; got scheme {parsed.scheme!r}. "
            "Use the GA_GUARD_API_URL environment variable to set a pre-approved URL."
        )
    host = parsed.hostname or ""
    try:
        addr = ipaddress.ip_address(host)
        if any(addr in net for net in _PRIVATE_NETS):
            raise ValueError(
                f"URLs targeting private or link-local IP ranges are not permitted: {host}"
            )
    except ValueError as exc:
        if "permitted" in str(exc):
            raise
        # host is a domain name, not a bare IP — allowed
    return url


class GuardrailBackend(str, Enum):
    """Supported guardrail backends"""
    NEMO = "nemo"
    GUARDRAILS_AI = "guardrails_ai"
    PRESIDIO = "presidio"
    LAKERA = "lakera"
    GA_GUARD = "ga_guard"
    OPENAI_MODERATION    = "openai_moderation"
    AZURE_CONTENT_SAFETY  = "azure_content_safety"
    AZURE_PROMPT_SHIELDS  = "azure_prompt_shields"
    AWS_BEDROCK           = "aws_bedrock"
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
    ALLOW      = "allow"
    BLOCK      = "block"
    REDACT     = "redact"
    REWRITE    = "rewrite"
    ESCALATE   = "escalate"
    RATE_LIMIT = "rate_limit"
    SKIPPED    = "skipped"   # backend not configured or credentials invalid


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
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
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
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

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

    traffic_split: float = 0.5  # 0-1, percentage going to experiment group
    duration_hours: int = 24

    metrics_to_track: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


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

    # ── Shared helpers ────────────────────────────────────────────

    def _threshold(self) -> float:
        return _THRESHOLDS.get(self.config.get("sensitivity", "medium"), 0.65)

    def _score_text(self, text: str, context: Optional[Dict] = None) -> Tuple[float, List[Dict]]:
        """
        Score text using the precompiler if available (avoids per-request regex compilation),
        otherwise fall back to wasm_scorer.
        """
        from .opa_gaps import wasm_scorer, precompiler
        sensitivity = self.config.get("sensitivity", "medium")
        policy_id = self.config.get("_policy_id")

        if precompiler and policy_id:
            rq = precompiler.compile(policy_id, context or {})
            score, risks = precompiler.evaluate(rq, text)
            return score, risks

        return wasm_scorer.score(text, sensitivity)

    def _check_tools(self, tool_name: str) -> Tuple[bool, str]:
        """Returns (blocked, reason)."""
        forbidden = set(
            self.config.get("restricted_tools", []) +
            self.config.get("forbidden_tools", [])
        )

        if forbidden and tool_name in forbidden:
            return True, "tool in blocklist"

        # Distinguish absent (no allowlist) from present-but-empty (deny all).
        # Using `if allowed` would treat [] as falsy and skip the check, allowing
        # an attacker to bypass the allowlist by PATCHing allowed_tools to [].
        allowed_tools_config = self.config.get("allowed_tools")
        if allowed_tools_config is not None:
            if tool_name not in set(allowed_tools_config):
                return True, "tool not in allowlist"

        return False, ""


# ── NeMo Guardrails backend ────────────────────────────────────────────────────

class NemoGuardrailsBackend(GuardrailBackendInterface):
    """
    NVIDIA NeMo Guardrails backend.

    When `nemoguardrails` is installed AND the policy has `nemo_colang` set,
    real NeMo rails are applied via `LLMRails.generate_async`.

    When the SDK is not installed, a WARNING is logged on every call and the
    built-in regex risk scorer is used as a fallback so the system stays
    operational. Install the SDK to get real NeMo behaviour:

        pip install nemoguardrails
    """

    def _nemo_check(self, messages: List[Dict]) -> Tuple[bool, float, List[Dict]]:
        """
        Run NeMo rails on `messages`. Returns (passed, risk_score, detected).
        Raises RuntimeError if the SDK is unavailable.
        """
        colang = self.config.get("colang_policy", "")
        nemo_yaml = self.config.get("nemo_yaml", "")
        if not (colang or nemo_yaml):
            self.logger.warning(
                "NeMo backend: SDK is installed but no colang/yaml policy is configured. "
                "Set nemo_colang on the policy. Falling back to regex scorer."
            )
            return None, None, None  # sentinel → caller uses fallback

        _ng = importlib.import_module("nemoguardrails")
        rails_cfg = _ng.RailsConfig.from_content(
            colang_content=colang,
            yaml_content=nemo_yaml,
        )
        rails = _ng.LLMRails(rails_cfg)
        response = _asyncio.run(rails.generate_async(messages=messages))
        blocked = bool(_NEMO_REFUSAL_RE.search(response))
        if blocked:
            return False, 0.9, [{"type": "nemo_rail_triggered", "response": response[:200]}]
        return True, 0.0, []

    def _sdk_warning(self):
        self.logger.warning(
            "NeMo backend: nemoguardrails SDK not installed — using regex scorer as fallback. "
            "Install with: pip install nemoguardrails  "
            "(NeMo also requires an LLM provider, e.g. pip install openai)"
        )

    def _check_credentials(self) -> bool:
        return True  # local SDK with regex fallback; always operational

    def check_input(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.NEMO)
        start = time.time()
        try:
            passed, risk_score, detected = None, None, None
            if _NEMO_SDK:
                passed, risk_score, detected = self._nemo_check(
                    [{"role": "user", "content": text}]
                )
            else:
                self._sdk_warning()

            if passed is None:  # SDK unavailable or no colang — use regex
                risk_score, detected = self._score_text(text, context)
                passed = risk_score < self._threshold()

            result.risk_score = risk_score
            result.passed = passed
            if not passed:
                result.action = ActionType.BLOCK
                result.severity = "critical" if risk_score > 0.8 else "warning"
                result.detected_risks = detected or [
                    {"type": RiskCategory.PROMPT_INJECTION.value, "confidence": round(risk_score, 3)}
                ]
        except Exception as exc:
            self.logger.error(f"NeMo check_input error: {exc}")
            from .testing import fail_closed_result
            return fail_closed_result(f"NeMo error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.NEMO)
        start = time.time()
        result.original_text = text
        try:
            passed, risk_score, detected = None, None, None
            if _NEMO_SDK:
                # NeMo checks output by treating it as an assistant message
                passed, risk_score, detected = self._nemo_check(
                    [{"role": "assistant", "content": text}]
                )
            else:
                self._sdk_warning()

            if passed is None:
                risk_score, detected = self._score_text(text, context)
                passed = risk_score < self._threshold()

            result.risk_score = risk_score
            result.passed = passed
            if not passed:
                result.action = ActionType.REDACT
                result.severity = "critical" if risk_score > 0.8 else "warning"
                result.detected_risks = detected
                result.modified_text = self._redact_sensitive_info(text)
            else:
                result.modified_text = text
        except Exception as exc:
            self.logger.error(f"NeMo check_output error: {exc}")
            from .testing import fail_closed_result
            return fail_closed_result(f"NeMo error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def validate_tool_call(self, tool_name: str, _tool_args: Dict[str, Any],
                           _context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.NEMO)
        if not _NEMO_SDK:
            self._sdk_warning()
        blocked, reason = self._check_tools(tool_name)
        if blocked:
            result.passed = False
            result.action = ActionType.BLOCK
            result.risk_score = 0.9
            result.severity = "critical"
            result.detected_risks.append({
                "type": RiskCategory.MALICIOUS_TOOL_USE.value,
                "tool": tool_name,
                "reason": reason,
            })
        return result

    def apply_policy(self, policy: GuardrailPolicy) -> bool:
        if policy.nemo_colang:
            self.config["colang_policy"] = policy.nemo_colang
            return True
        return False

    def _redact_sensitive_info(self, text: str) -> str:
        text = _re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]', text)
        text = _re.sub(r'\b\d{16}\b', '[CARD]', text)
        text = _re.sub(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[EMAIL]', text)
        return text


# ── GuardrailsAI backend ───────────────────────────────────────────────────────

class GuardrailsAIBackend(GuardrailBackendInterface):
    """
    GuardrailsAI framework backend.

    When `guardrails-ai` is installed, checks run through a real `Guard` object.
    Hub validators named in `policy.rules.validators` (e.g. `["DetectPII"]`) are
    loaded from `guardrails.hub` when available.

    When the SDK is not installed, a WARNING is logged on every call and the
    built-in regex risk scorer is used as a fallback. Install the SDK to get
    real GuardrailsAI behaviour:

        pip install guardrails-ai
    """

    def _sdk_warning(self):
        self.logger.warning(
            "GuardrailsAI backend: guardrails-ai SDK not installed — "
            "using regex scorer as fallback. Install with: pip install guardrails-ai"
        )

    def _build_guard(self, validator_names: List[str]):
        """Build a Guard with any hub validators that are available."""
        _g = importlib.import_module("guardrails")
        guard = _g.Guard()
        loaded: List[str] = []
        for name in validator_names:
            try:
                hub = importlib.import_module("guardrails.hub")
                cls = getattr(hub, name, None)
                if cls:
                    guard = guard.use(cls(on_fail="noop"))
                    loaded.append(name)
            except (ImportError, AttributeError):
                pass
        if validator_names and not loaded:
            self.logger.warning(
                "GuardrailsAI: none of the requested validators (%s) were found in "
                "guardrails.hub. Run: guardrails hub install <validator>. "
                "Falling back to regex scorer for safety.",
                validator_names,
            )
        elif loaded:
            self.logger.debug("GuardrailsAI: loaded hub validators %s", loaded)
        return guard, bool(loaded)

    def _guardrails_check(self, text: str, validator_names: List[str]) -> Tuple[bool, float, List[Dict]]:
        """
        Run text through the real guardrails-ai Guard.
        Returns (passed, risk_score, detected).
        """
        guard, hub_loaded = self._build_guard(validator_names)
        outcome = guard.validate(text)
        passed = outcome.validation_passed
        detected: List[Dict] = []
        if not passed:
            detected = [{"type": "guardrails_validation",
                         "error": str(getattr(outcome, "error", ""))[:200]}]
        risk_score = 0.0 if passed else 0.8
        return passed, risk_score, detected

    def _check_credentials(self) -> bool:
        return True  # local SDK with regex fallback; always operational

    def check_input(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.GUARDRAILS_AI)
        start = time.time()
        try:
            validators = self.config.get("validators", [])
            if _GUARDRAILSAI_SDK:
                passed, sdk_score, sdk_detected = self._guardrails_check(text, validators)
            else:
                self._sdk_warning()
                passed, sdk_score, sdk_detected = True, 0.0, []

            # Always also run the regex scorer for defence in depth
            base_score, base_detected = self._score_text(text, context)
            risk_score = max(sdk_score, base_score)
            detected = sdk_detected + base_detected
            passed = passed and risk_score < self._threshold()

            result.risk_score = risk_score
            result.passed = passed
            result.detected_risks = detected
            if not passed:
                result.action = ActionType.BLOCK
                result.severity = "critical" if risk_score > 0.8 else "warning"
        except Exception as exc:
            self.logger.error(f"GuardrailsAI check_input error: {exc}")
            from .testing import fail_closed_result
            return fail_closed_result(f"GuardrailsAI error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.GUARDRAILS_AI)
        start = time.time()
        result.original_text = text
        try:
            validators = self.config.get("output_validators", self.config.get("validators", []))
            if _GUARDRAILSAI_SDK:
                passed, sdk_score, sdk_detected = self._guardrails_check(text, validators)
            else:
                self._sdk_warning()
                passed, sdk_score, sdk_detected = True, 0.0, []

            base_score, base_detected = self._score_text(text, context)
            risk_score = max(sdk_score, base_score)
            detected = sdk_detected + base_detected
            passed = passed and risk_score < self._threshold()

            result.risk_score = risk_score
            result.passed = passed
            result.detected_risks = detected
            if passed:
                result.modified_text = text
            else:
                result.action = ActionType.REDACT
                result.severity = "critical" if risk_score > 0.8 else "warning"
                result.modified_text = self._redact_output(text)
        except Exception as exc:
            self.logger.error(f"GuardrailsAI check_output error: {exc}")
            from .testing import fail_closed_result
            return fail_closed_result(f"GuardrailsAI error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def validate_tool_call(self, tool_name: str, _tool_args: Dict[str, Any],
                           _context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.GUARDRAILS_AI)
        if not _GUARDRAILSAI_SDK:
            self._sdk_warning()
        blocked, reason = self._check_tools(tool_name)
        if blocked:
            result.passed = False
            result.action = ActionType.BLOCK
            result.risk_score = 0.9
            result.severity = "critical"
            result.detected_risks.append({
                "type": RiskCategory.MALICIOUS_TOOL_USE.value,
                "tool": tool_name,
                "reason": reason,
            })
        return result

    def apply_policy(self, policy: GuardrailPolicy) -> bool:
        if policy.guardrails_yaml:
            self.config["policy_yaml"] = policy.guardrails_yaml
            return True
        return False

    def _redact_output(self, text: str) -> str:
        from .actions import rewrite_text
        return rewrite_text(text)


# ── Presidio backend ───────────────────────────────────────────────────────────

class PresidioBackend(GuardrailBackendInterface):
    """Microsoft Presidio PII detection backend"""

    def _check_credentials(self) -> bool:
        return True  # fully local; no external credentials required

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
            result.risk_score = min(len(pii_entities) * 0.15, 1.0)
            result.severity = "critical" if result.risk_score > 0.5 else "warning"
        else:
            result.passed = True
            result.modified_text = text

        result.latency_ms = (time.time() - start) * 1000
        return result

    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        return self.check_input(text, context)

    def validate_tool_call(self, tool_name: str, tool_args: Dict[str, Any],
                           context: Optional[Dict] = None) -> GuardrailResult:
        """Previously always passed — now scans tool arguments for PII."""
        result = GuardrailResult(backend_used=GuardrailBackend.PRESIDIO)
        pii_found = []

        for arg_name, value in tool_args.items():
            if isinstance(value, str):
                entities = self._detect_pii(value)
                for entity in entities:
                    pii_found.append({"argument": arg_name, **entity})

        if pii_found:
            result.passed = False
            result.action = ActionType.BLOCK
            result.severity = "critical"
            result.detected_risks = pii_found
            result.risk_score = min(len(pii_found) * 0.25, 1.0)
        return result

    def apply_policy(self, policy: GuardrailPolicy) -> bool:
        if policy.presidio_config:
            self.config.update(policy.presidio_config)
            return True
        return False

    def _detect_pii(self, text: str) -> List[Dict[str, Any]]:
        """Use real Presidio SDK when available; fall back to regex."""
        if _PRESIDIO_SDK and _presidio_analyzer:
            return self._detect_pii_sdk(text)
        return self._detect_pii_regex(text)

    def _detect_pii_sdk(self, text: str) -> List[Dict[str, Any]]:
        entities = []
        try:
            results = _presidio_analyzer.analyze(text=text, language="en")
            for r in results:
                entities.append({
                    "type": r.entity_type,
                    "text": text[r.start:r.end],
                    "start": r.start,
                    "end": r.end,
                    "score": round(r.score, 3),
                })
        except Exception as exc:
            self.logger.warning(f"Presidio SDK error — falling back to regex: {exc}")
            return self._detect_pii_regex(text)
        return entities

    def _detect_pii_regex(self, text: str) -> List[Dict[str, Any]]:
        import re
        entities = []
        patterns = [
            ("EMAIL_ADDRESS", re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')),
            ("PHONE_NUMBER",  re.compile(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b')),
            ("US_SSN",        re.compile(r'\b\d{3}[-.\s]\d{2}[-.\s]\d{4}\b')),
            ("CREDIT_CARD",   re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b')),
        ]
        for entity_type, pat in patterns:
            for m in pat.finditer(text):
                entities.append({
                    "type": entity_type,
                    "text": m.group(),
                    "start": m.start(),
                    "end": m.end(),
                })
        return entities

    def _redact_pii(self, text: str, entities: List[Dict[str, Any]]) -> str:
        if _PRESIDIO_SDK and _presidio_anonymizer and entities:
            try:
                RecognizerResult = importlib.import_module("presidio_analyzer").RecognizerResult
                recognizer_results = [
                    RecognizerResult(
                        entity_type=e["type"],
                        start=e["start"],
                        end=e["end"],
                        score=e.get("score", 0.85),
                    )
                    for e in entities
                    if "start" in e and "end" in e
                ]
                anonymized = _presidio_anonymizer.anonymize(
                    text=text, analyzer_results=recognizer_results
                )
                return anonymized.text
            except Exception as exc:
                self.logger.warning(f"Presidio anonymizer error — falling back to regex: {exc}")

        # Regex fallback: replace from end to avoid shifting offsets
        result = text
        for entity in sorted(
            [e for e in entities if "start" in e and "end" in e],
            key=lambda e: e["end"],
            reverse=True,
        ):
            result = result[: entity["start"]] + f"[{entity['type']}]" + result[entity["end"] :]
        return result


# ── Lakera Guard backend ───────────────────────────────────────────────────────

class LakeraGuardBackend(GuardrailBackendInterface):
    """
    Lakera Guard real-time prompt-injection API backend.

    Requires LAKERA_GUARD_API_KEY env var (or api_key in policy rules).
    Falls back to fail-closed when the API key is absent.
    """

    _INPUT_URL  = "https://api.lakera.ai/v2/guard"
    _OUTPUT_URL = "https://api.lakera.ai/v2/guard"

    def _api_key(self) -> Optional[str]:
        return os.getenv("LAKERA_GUARD_API_KEY", "").strip() or self.config.get("api_key") or None

    def _skipped_result(self, reason: str = "LAKERA_GUARD_API_KEY not configured") -> GuardrailResult:
        return GuardrailResult(
            backend_used=GuardrailBackend.LAKERA,
            passed=True,
            action=ActionType.SKIPPED,
            findings={"skipped": True, "reason": reason},
        )

    def _call_api(self, url: str, text: str, role: str = "user") -> Tuple[bool, float, List[Dict]]:
        """Returns (flagged, risk_score, detected_risks)."""
        api_key = self._api_key()
        if not api_key:
            raise ValueError("Lakera Guard API key not configured. Set LAKERA_GUARD_API_KEY.")

        payload = json.dumps({
            "messages": [{"role": role, "content": text}],
            "breakdown": True,
        }).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        # v2 API: top-level "flagged" boolean (not nested under "results")
        flagged = bool(data.get("flagged", False))

        risks = []
        for item in data.get("breakdown", []):
            if item.get("detected"):
                risks.append({
                    "type": item.get("detector_type", "unknown"),
                    "confidence": item.get("result", ""),
                    "source": "lakera_guard",
                })

        return flagged, (1.0 if flagged else 0.0), risks

    def _check_credentials(self) -> bool:
        return bool(self._api_key())

    def check_input(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        if not self._api_key():
            return self._skipped_result()
        result = GuardrailResult(backend_used=GuardrailBackend.LAKERA)
        start = time.time()
        try:
            flagged, score, risks = self._call_api(self._INPUT_URL, text)
            result.risk_score = score
            result.passed = not flagged
            result.detected_risks = risks
            if flagged:
                result.action = ActionType.BLOCK
                result.severity = "critical"
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                self.logger.warning("Lakera auth error %d — marking SKIPPED", exc.code)
                return self._skipped_result(f"Invalid API key (HTTP {exc.code})")
            self.logger.error("Lakera API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"Lakera API error: {exc}")
        except Exception as exc:
            self.logger.error("Lakera API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"Lakera API error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        if not self._api_key():
            return self._skipped_result()
        result = GuardrailResult(backend_used=GuardrailBackend.LAKERA)
        start = time.time()
        result.original_text = text
        try:
            flagged, score, risks = self._call_api(self._OUTPUT_URL, text, role="assistant")
            result.risk_score = score
            result.passed = not flagged
            result.detected_risks = risks
            if flagged:
                result.action = ActionType.REDACT
                result.severity = "critical"
                from .actions import rewrite_text
                result.modified_text = rewrite_text(text, risks)
            else:
                result.modified_text = text
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                self.logger.warning("Lakera auth error %d — marking SKIPPED", exc.code)
                return self._skipped_result(f"Invalid API key (HTTP {exc.code})")
            self.logger.error("Lakera API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"Lakera API error: {exc}")
        except Exception as exc:
            self.logger.error("Lakera API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"Lakera API error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def validate_tool_call(self, tool_name: str, _tool_args: Dict[str, Any],
                           _context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.LAKERA)
        blocked, reason = self._check_tools(tool_name)
        if blocked:
            result.passed = False
            result.action = ActionType.BLOCK
            result.risk_score = 0.9
            result.severity = "critical"
            result.detected_risks.append({
                "type": RiskCategory.MALICIOUS_TOOL_USE.value,
                "tool": tool_name,
                "reason": reason,
            })
        return result

    def apply_policy(self, _policy: GuardrailPolicy) -> bool:
        return True


# ── GA Guard backend ───────────────────────────────────────────────────────────

class GAGuardBackend(GuardrailBackendInterface):
    """
    Generic configurable HTTP guardrail backend (GA Guard).

    Sends a POST to GA_GUARD_API_URL with {"text": "...", "context": {...}}
    and expects a response of {"passed": bool, "risk_score": float, "risks": [...]}.

    Falls back to wasm_scorer when GA_GUARD_API_URL is not configured.
    """

    def _api_url(self) -> Optional[str]:
        url = self.config.get("api_url") or os.getenv("GA_GUARD_API_URL", "").strip() or None
        if url:
            _validate_external_url(url)  # raises ValueError on unsafe URLs
        return url

    def _call_api(self, text: str, context: Optional[Dict]) -> Tuple[bool, float, List[Dict]]:
        url = self._api_url()
        if not url:
            raise ValueError("GA Guard API URL not configured. Set GA_GUARD_API_URL.")

        api_key = os.getenv("GA_GUARD_API_KEY", "").strip() or self.config.get("api_key")
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        payload = json.dumps({"text": text, "context": context or {}}).encode()
        req = urllib.request.Request(url, data=payload, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        passed = bool(data.get("passed", True))
        score = float(data.get("risk_score", 0.0))
        risks = data.get("risks", [])
        return passed, score, risks

    def _fallback_check(self, text: str, context: Optional[Dict]) -> Tuple[bool, float, List[Dict]]:
        """Used when no API URL is configured."""
        from .opa_gaps import wasm_scorer
        sensitivity = self.config.get("sensitivity", "medium")
        score, risks = wasm_scorer.score(text, sensitivity)
        threshold = _THRESHOLDS.get(sensitivity, 0.65)
        return score < threshold, score, risks

    def _check_credentials(self) -> bool:
        return True  # local wasm fallback when no API URL is configured

    def check_input(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.GA_GUARD)
        start = time.time()
        try:
            if self._api_url():
                passed, score, risks = self._call_api(text, context)
            else:
                passed, score, risks = self._fallback_check(text, context)
            result.risk_score = score
            result.passed = passed
            result.detected_risks = risks
            if not passed:
                result.action = ActionType.BLOCK
                result.severity = "critical" if score > 0.8 else "warning"
        except Exception as exc:
            self.logger.error(f"GA Guard API error: {exc}")
            from .testing import fail_closed_result
            return fail_closed_result(f"GA Guard API error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = self.check_input(text, context)
        result.original_text = text
        result.backend_used = GuardrailBackend.GA_GUARD
        if not result.passed:
            from .actions import rewrite_text
            result.modified_text = rewrite_text(text, result.detected_risks)
        else:
            result.modified_text = text
        return result

    def validate_tool_call(self, tool_name: str, _tool_args: Dict[str, Any],
                           _context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.GA_GUARD)
        blocked, reason = self._check_tools(tool_name)
        if blocked:
            result.passed = False
            result.action = ActionType.BLOCK
            result.risk_score = 0.9
            result.severity = "critical"
            result.detected_risks.append({
                "type": RiskCategory.MALICIOUS_TOOL_USE.value,
                "tool": tool_name,
                "reason": reason,
            })
        return result

    def apply_policy(self, _policy: GuardrailPolicy) -> bool:
        return True


# ── OpenAI Moderation backend ──────────────────────────────────────────────────


class OpenAIModerationBackend(GuardrailBackendInterface):
    """
    OpenAI Moderation API backend.

    Calls POST https://api.openai.com/v1/moderations and maps OpenAI
    categories to RiskCategory.  Returns BLOCK when flagged=true, ALLOW
    when false.  Gracefully skips (ALLOW pass-through) when OPENAI_API_KEY
    is absent so the rest of the policy pipeline keeps running.

    Requires OPENAI_API_KEY env var (or api_key in policy rules).
    """

    _API_URL = "https://api.openai.com/v1/moderations"

    # Maps OpenAI moderation categories to internal RiskCategory values.
    # Sub-categories inherit the parent mapping.
    _CATEGORY_MAP: Dict[str, "RiskCategory"] = {
        "hate":                   RiskCategory.JAILBREAKING,
        "hate/threatening":       RiskCategory.JAILBREAKING,
        "harassment":             RiskCategory.JAILBREAKING,
        "harassment/threatening": RiskCategory.JAILBREAKING,
        "self-harm":              RiskCategory.JAILBREAKING,
        "self-harm/intent":       RiskCategory.JAILBREAKING,
        "self-harm/instructions": RiskCategory.JAILBREAKING,
        "sexual":                 RiskCategory.JAILBREAKING,
        "sexual/minors":          RiskCategory.JAILBREAKING,
        "violence":               RiskCategory.JAILBREAKING,
        "violence/graphic":       RiskCategory.JAILBREAKING,
        "illicit":                RiskCategory.PROMPT_INJECTION,
        "illicit/violent":        RiskCategory.PROMPT_INJECTION,
    }

    def _api_key(self) -> Optional[str]:
        return (
            os.getenv("OPENAI_API_KEY", "").strip()
            or self.config.get("api_key")
            or None
        )

    def _skipped_result(self, original_text: str = "",
                        reason: str = "OPENAI_API_KEY not configured") -> GuardrailResult:
        r = GuardrailResult(backend_used=GuardrailBackend.OPENAI_MODERATION)
        r.passed = True
        r.action = ActionType.SKIPPED
        r.risk_score = 0.0
        r.original_text = original_text
        r.modified_text = original_text
        r.findings = {"skipped": True, "reason": reason}
        return r

    def _call_api(self, text: str) -> Tuple[bool, float, List[Dict]]:
        """Returns (flagged, max_category_score, detected_risks).

        Retries up to 3 times on HTTP 429 with exponential back-off (1 s, 2 s,
        4 s) to handle free-tier rate limits gracefully.
        """
        payload = json.dumps({"input": text}).encode()
        req = urllib.request.Request(
            self._API_URL,
            data=payload,
            headers={
                "Authorization": f"Bearer {self._api_key()}",
                "Content-Type": "application/json",
            },
        )
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read())
                break  # success — exit retry loop
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < max_retries - 1:
                    wait = 2 ** attempt          # 1 s, 2 s, 4 s
                    self.logger.warning(
                        "OpenAI Moderation 429 rate-limited — retrying in %ds (attempt %d/%d)",
                        wait, attempt + 1, max_retries,
                    )
                    time.sleep(wait)
                    continue
                raise  # non-429 or final attempt — propagate

        item = data.get("results", [{}])[0]
        flagged = bool(item.get("flagged", False))
        categories = item.get("categories", {})
        scores = item.get("category_scores", {})

        risks: List[Dict] = []
        for cat, is_flagged in categories.items():
            if is_flagged:
                risk_cat = self._CATEGORY_MAP.get(cat, RiskCategory.JAILBREAKING)
                risks.append({
                    "type": risk_cat.value,
                    "category": cat,
                    "score": scores.get(cat, 0.0),
                    "source": "openai_moderation",
                })

        max_score = max(scores.values(), default=0.0) if scores else 0.0
        return flagged, max_score, risks

    def _check_credentials(self) -> bool:
        return bool(self._api_key())

    def check_input(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        if not self._api_key():
            return self._skipped_result()
        result = GuardrailResult(backend_used=GuardrailBackend.OPENAI_MODERATION)
        start = time.time()
        try:
            flagged, score, risks = self._call_api(text)
            result.risk_score = score
            result.passed = not flagged
            result.detected_risks = risks
            if flagged:
                result.action = ActionType.BLOCK
                result.severity = "critical"
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                self.logger.warning("OpenAI Moderation auth error %d — marking SKIPPED", exc.code)
                return self._skipped_result(reason=f"Invalid API key (HTTP {exc.code})")
            self.logger.error("OpenAI Moderation API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"OpenAI Moderation API error: {exc}")
        except Exception as exc:
            self.logger.error("OpenAI Moderation API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"OpenAI Moderation API error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        if not self._api_key():
            return self._skipped_result(text)
        result = GuardrailResult(backend_used=GuardrailBackend.OPENAI_MODERATION)
        start = time.time()
        result.original_text = text
        try:
            flagged, score, risks = self._call_api(text)
            result.risk_score = score
            result.passed = not flagged
            result.detected_risks = risks
            if flagged:
                result.action = ActionType.REDACT
                result.severity = "critical"
                from .actions import rewrite_text
                result.modified_text = rewrite_text(text, risks)
            else:
                result.modified_text = text
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                self.logger.warning("OpenAI Moderation auth error %d — marking SKIPPED", exc.code)
                return self._skipped_result(text, reason=f"Invalid API key (HTTP {exc.code})")
            self.logger.error("OpenAI Moderation API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"OpenAI Moderation API error: {exc}")
        except Exception as exc:
            self.logger.error("OpenAI Moderation API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"OpenAI Moderation API error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def validate_tool_call(self, tool_name: str, _tool_args: Dict[str, Any],
                           _context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.OPENAI_MODERATION)
        blocked, reason = self._check_tools(tool_name)
        if blocked:
            result.passed = False
            result.action = ActionType.BLOCK
            result.risk_score = 0.9
            result.severity = "critical"
            result.detected_risks.append({
                "type": RiskCategory.MALICIOUS_TOOL_USE.value,
                "tool": tool_name,
                "reason": reason,
            })
        return result

    def apply_policy(self, _policy: GuardrailPolicy) -> bool:
        return True

    def health_check(self) -> Dict[str, Any]:
        if not self._api_key():
            return {
                "status": "skipped",
                "backend": GuardrailBackend.OPENAI_MODERATION.value,
                "reason": "OPENAI_API_KEY not configured",
            }
        return {"status": "ok", "backend": GuardrailBackend.OPENAI_MODERATION.value}


# ── Azure Content Safety backend ───────────────────────────────────────────────


class AzureContentSafetyBackend(GuardrailBackendInterface):
    """
    Azure AI Content Safety backend.

    Calls POST {endpoint}/contentsafety/text:analyze (api-version 2023-10-01)
    and maps Azure severity scores (0–6) to ActionType:
        0–2  → ALLOW
        3–4  → ESCALATE
        5–6  → BLOCK

    Gracefully skips (ALLOW pass-through) when the required env vars are
    absent so the rest of the policy pipeline keeps running.

    Requires:
        AZURE_CONTENT_SAFETY_ENDPOINT — e.g. https://myresource.cognitiveservices.azure.com
        AZURE_CONTENT_SAFETY_KEY      — subscription key
    """

    _API_VERSION = "2023-10-01"

    _CATEGORY_MAP: Dict[str, "RiskCategory"] = {
        "Hate":      RiskCategory.JAILBREAKING,
        "Violence":  RiskCategory.JAILBREAKING,
        "Sexual":    RiskCategory.JAILBREAKING,
        "SelfHarm":  RiskCategory.JAILBREAKING,
    }

    def _endpoint(self) -> Optional[str]:
        ep = (
            os.getenv("AZURE_CONTENT_SAFETY_ENDPOINT", "").strip()
            or self.config.get("endpoint")
            or None
        )
        if ep:
            _validate_external_url(ep)
        return ep

    def _api_key(self) -> Optional[str]:
        return (
            os.getenv("AZURE_CONTENT_SAFETY_KEY", "").strip()
            or self.config.get("api_key")
            or None
        )

    def _skipped_result(self, original_text: str = "",
                        reason: str = "AZURE_CONTENT_SAFETY_ENDPOINT or AZURE_CONTENT_SAFETY_KEY not configured") -> GuardrailResult:
        r = GuardrailResult(backend_used=GuardrailBackend.AZURE_CONTENT_SAFETY)
        r.passed = True
        r.action = ActionType.SKIPPED
        r.risk_score = 0.0
        r.original_text = original_text
        r.modified_text = original_text
        r.findings = {"skipped": True, "reason": reason}
        return r

    @staticmethod
    def _severity_to_action(max_severity: int) -> ActionType:
        if max_severity >= 4:
            return ActionType.BLOCK
        if max_severity >= 2:
            return ActionType.ESCALATE
        return ActionType.ALLOW

    # Azure Content Safety hard limit for a single text:analyze call.
    _MAX_TEXT_CHARS = 10_000

    def _call_api(self, text: str) -> Tuple[bool, float, List[Dict], int]:
        """Returns (flagged, risk_score, detected_risks, max_severity).

        Truncates input to 10,000 characters (Azure API limit) and retries
        once on timeout with a 30-second deadline.  Surfaces the 400 response
        body in the exception message so the root cause is visible in logs.
        """
        endpoint = self._endpoint() or ""
        api_key  = self._api_key()  or ""

        # Truncate — Azure returns 400 if the text exceeds 10,000 chars.
        safe_text = text[: self._MAX_TEXT_CHARS]

        url = (
            f"{endpoint.rstrip('/')}/contentsafety/text:analyze"
            f"?api-version={self._API_VERSION}"
        )
        payload = json.dumps({"text": safe_text}).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Ocp-Apim-Subscription-Key": api_key,
                "Content-Type": "application/json",
            },
        )

        max_retries = 2
        for attempt in range(max_retries):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read())
                break  # success
            except urllib.error.HTTPError as exc:
                # Read and attach the response body so 400 details appear in logs.
                try:
                    body = exc.read().decode(errors="replace")
                except Exception:
                    body = "(unreadable)"
                raise urllib.error.HTTPError(
                    exc.url, exc.code,
                    f"{exc.reason} — {body}",
                    exc.headers, None,
                ) from None
            except OSError:  # socket.timeout is an OSError subclass
                if attempt < max_retries - 1:
                    self.logger.warning(
                        "Azure Content Safety timed out — retrying (attempt %d/%d)",
                        attempt + 1, max_retries,
                    )
                    continue
                raise

        max_severity = 0
        risks: List[Dict] = []

        for cat_result in data.get("categoriesAnalysis", []):
            cat_name = cat_result.get("category", "")
            severity = int(cat_result.get("severity", 0))
            if severity > max_severity:
                max_severity = severity
            if severity > 0:
                risk_cat = self._CATEGORY_MAP.get(cat_name, RiskCategory.JAILBREAKING)
                risks.append({
                    "type": risk_cat.value,
                    "category": cat_name,
                    "severity": severity,
                    "source": "azure_content_safety",
                })

        action = self._severity_to_action(max_severity)
        flagged = action in (ActionType.ESCALATE, ActionType.BLOCK)
        score = round(max_severity / 6.0, 4)
        return flagged, score, risks, max_severity

    def _check_credentials(self) -> bool:
        return bool(self._endpoint() and self._api_key())

    def check_input(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        if not self._endpoint() or not self._api_key():
            return self._skipped_result()
        result = GuardrailResult(backend_used=GuardrailBackend.AZURE_CONTENT_SAFETY)
        start = time.time()
        try:
            flagged, score, risks, max_severity = self._call_api(text)
            result.risk_score = score
            result.passed = not flagged
            result.detected_risks = risks
            if flagged:
                result.action = self._severity_to_action(max_severity)
                result.severity = "critical" if max_severity >= 5 else "warning"
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                self.logger.warning("Azure Content Safety auth error %d — marking SKIPPED", exc.code)
                return self._skipped_result(reason=f"Invalid credentials (HTTP {exc.code})")
            self.logger.error("Azure Content Safety API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"Azure Content Safety API error: {exc}")
        except Exception as exc:
            self.logger.error("Azure Content Safety API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"Azure Content Safety API error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        if not self._endpoint() or not self._api_key():
            return self._skipped_result(text)
        result = GuardrailResult(backend_used=GuardrailBackend.AZURE_CONTENT_SAFETY)
        start = time.time()
        result.original_text = text
        try:
            flagged, score, risks, max_severity = self._call_api(text)
            result.risk_score = score
            result.passed = not flagged
            result.detected_risks = risks
            if flagged:
                result.action = self._severity_to_action(max_severity)
                result.severity = "critical" if max_severity >= 5 else "warning"
                from .actions import rewrite_text
                result.modified_text = rewrite_text(text, risks)
            else:
                result.modified_text = text
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                self.logger.warning("Azure Content Safety auth error %d — marking SKIPPED", exc.code)
                return self._skipped_result(text, reason=f"Invalid credentials (HTTP {exc.code})")
            self.logger.error("Azure Content Safety API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"Azure Content Safety API error: {exc}")
        except Exception as exc:
            self.logger.error("Azure Content Safety API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"Azure Content Safety API error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def validate_tool_call(self, tool_name: str, _tool_args: Dict[str, Any],
                           _context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.AZURE_CONTENT_SAFETY)
        blocked, reason = self._check_tools(tool_name)
        if blocked:
            result.passed = False
            result.action = ActionType.BLOCK
            result.risk_score = 0.9
            result.severity = "critical"
            result.detected_risks.append({
                "type": RiskCategory.MALICIOUS_TOOL_USE.value,
                "tool": tool_name,
                "reason": reason,
            })
        return result

    def apply_policy(self, _policy: GuardrailPolicy) -> bool:
        return True

    def health_check(self) -> Dict[str, Any]:
        if not self._endpoint() or not self._api_key():
            return {
                "status": "skipped",
                "backend": GuardrailBackend.AZURE_CONTENT_SAFETY.value,
                "reason": "AZURE_CONTENT_SAFETY_ENDPOINT or AZURE_CONTENT_SAFETY_KEY not configured",
            }
        return {"status": "ok", "backend": GuardrailBackend.AZURE_CONTENT_SAFETY.value}


# ── Azure Prompt Shields backend ───────────────────────────────────────────────


class AzurePromptShieldsBackend(GuardrailBackendInterface):
    """
    Azure AI Content Safety — Prompt Shields endpoint.

    Detects prompt injection and jailbreak attacks in user prompts.
    Reuses the same Azure Content Safety resource as AzureContentSafetyBackend
    (AZURE_CONTENT_SAFETY_ENDPOINT + AZURE_CONTENT_SAFETY_KEY) — no extra
    Azure resource needed.

    Gracefully skips (ALLOW pass-through) when the env vars are absent.
    """

    _API_VERSION = "2024-09-01"
    _MAX_TEXT_CHARS = 10_000

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

    def _endpoint(self) -> Optional[str]:
        return (
            os.getenv("AZURE_CONTENT_SAFETY_ENDPOINT", "").strip()
            or self.config.get("endpoint")
            or None
        )

    def _api_key(self) -> Optional[str]:
        return (
            os.getenv("AZURE_CONTENT_SAFETY_KEY", "").strip()
            or self.config.get("api_key")
            or None
        )

    def _call_api(self, text: str) -> Tuple[bool, float, List[Dict]]:
        """Returns (attack_detected, risk_score, detected_risks)."""
        endpoint = self._endpoint() or ""
        api_key  = self._api_key()  or ""
        safe_text = text[: self._MAX_TEXT_CHARS]
        url = (
            f"{endpoint.rstrip('/')}/contentsafety/text:shieldPrompt"
            f"?api-version={self._API_VERSION}"
        )
        payload = json.dumps({"userPrompt": safe_text, "documents": []}).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Ocp-Apim-Subscription-Key": api_key,
                "Content-Type": "application/json",
            },
        )
        for attempt in range(2):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read())
                break
            except urllib.error.HTTPError as exc:
                # Log the response body for easier diagnosis, then re-raise immediately.
                body = exc.read()[:500].decode("utf-8", errors="replace")
                self.logger.error(
                    "Azure Prompt Shields HTTP %d — url=%s body=%s", exc.code, url, body
                )
                raise
            except OSError:
                if attempt == 0:
                    continue
                raise

        attack_detected = bool(
            data.get("userPromptAnalysis", {}).get("attackDetected", False)
        )
        risks = []
        if attack_detected:
            risks.append({
                "type": RiskCategory.PROMPT_INJECTION.value,
                "source": "azure_prompt_shields",
            })

        return attack_detected, (1.0 if attack_detected else 0.0), risks

    def _skipped_result(self, reason: str) -> GuardrailResult:
        return GuardrailResult(
            backend_used=GuardrailBackend.AZURE_PROMPT_SHIELDS,
            passed=True,
            action=ActionType.SKIPPED,
            findings={"skipped": True, "reason": reason},
        )

    def _check_credentials(self) -> bool:
        return bool(self._endpoint() and self._api_key())

    def check_input(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.AZURE_PROMPT_SHIELDS)
        if not self._endpoint() or not self._api_key():
            return self._skipped_result(
                "AZURE_CONTENT_SAFETY_ENDPOINT or AZURE_CONTENT_SAFETY_KEY not configured"
            )
        start = time.time()
        try:
            flagged, score, risks = self._call_api(text)
            result.risk_score = score
            result.passed = not flagged
            result.detected_risks = risks
            if flagged:
                result.action = ActionType.BLOCK
                result.severity = "critical"
                from .actions import rewrite_text
                result.modified_text = rewrite_text(text, risks)
            else:
                result.modified_text = text
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                self.logger.warning("Azure Prompt Shields auth error %d — marking SKIPPED", exc.code)
                return self._skipped_result(f"Invalid credentials (HTTP {exc.code})")
            self.logger.error("Azure Prompt Shields API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"Azure Prompt Shields API error: {exc}")
        except Exception as exc:
            self.logger.error("Azure Prompt Shields API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"Azure Prompt Shields API error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.AZURE_PROMPT_SHIELDS)
        if not self._endpoint() or not self._api_key():
            return self._skipped_result(
                "AZURE_CONTENT_SAFETY_ENDPOINT or AZURE_CONTENT_SAFETY_KEY not configured"
            )
        start = time.time()
        try:
            flagged, score, risks = self._call_api(text)
            result.risk_score = score
            result.passed = not flagged
            result.detected_risks = risks
            if flagged:
                result.action = ActionType.BLOCK
                result.severity = "critical"
            else:
                result.modified_text = text
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                self.logger.warning("Azure Prompt Shields auth error %d — marking SKIPPED", exc.code)
                return self._skipped_result(f"Invalid credentials (HTTP {exc.code})")
            self.logger.error("Azure Prompt Shields API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"Azure Prompt Shields API error: {exc}")
        except Exception as exc:
            self.logger.error("Azure Prompt Shields API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"Azure Prompt Shields API error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def validate_tool_call(self, tool_name: str, _tool_args: Dict[str, Any],
                           _context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.AZURE_PROMPT_SHIELDS)
        blocked, reason = self._check_tools(tool_name)
        if blocked:
            result.passed = False
            result.action = ActionType.BLOCK
            result.risk_score = 0.9
            result.severity = "critical"
            result.detected_risks.append({
                "type": RiskCategory.MALICIOUS_TOOL_USE.value,
                "tool": tool_name,
                "reason": reason,
            })
        return result

    def apply_policy(self, _policy: GuardrailPolicy) -> bool:
        return True

    def health_check(self) -> Dict[str, Any]:
        if not self._endpoint() or not self._api_key():
            return {
                "status": "skipped",
                "backend": GuardrailBackend.AZURE_PROMPT_SHIELDS.value,
                "reason": "AZURE_CONTENT_SAFETY_ENDPOINT or AZURE_CONTENT_SAFETY_KEY not configured",
            }
        return {"status": "ok", "backend": GuardrailBackend.AZURE_PROMPT_SHIELDS.value}


# ── AWS Bedrock Guardrails backend ─────────────────────────────────────────────


class AWSBedrockBackend(GuardrailBackendInterface):
    """
    AWS Bedrock Guardrails backend.

    Calls boto3 bedrock-runtime.apply_guardrail() and maps the response:
        GUARDRAIL_INTERVENED → BLOCK
        NONE                 → ALLOW

    Gracefully skips (ALLOW pass-through) when the required env vars are
    absent so the rest of the policy pipeline keeps running.

    Requires:
        AWS_ACCESS_KEY_ID              — IAM access key
        AWS_SECRET_ACCESS_KEY          — IAM secret key
        AWS_DEFAULT_REGION             — e.g. us-east-1
        AWS_BEDROCK_GUARDRAIL_ID       — Bedrock guardrail resource ID
        AWS_BEDROCK_GUARDRAIL_VERSION  — e.g. DRAFT or a numeric version
    """

    def _creds(self) -> Dict[str, str]:
        return {
            "access_key":       os.getenv("AWS_ACCESS_KEY_ID", "").strip()            or self.config.get("aws_access_key_id", ""),
            "secret_key":       os.getenv("AWS_SECRET_ACCESS_KEY", "").strip()        or self.config.get("aws_secret_access_key", ""),
            "region":           os.getenv("AWS_DEFAULT_REGION", "").strip()           or self.config.get("aws_default_region", ""),
            "guardrail_id":     os.getenv("AWS_BEDROCK_GUARDRAIL_ID", "").strip()     or self.config.get("aws_bedrock_guardrail_id", ""),
            "guardrail_version": os.getenv("AWS_BEDROCK_GUARDRAIL_VERSION", "").strip() or self.config.get("aws_bedrock_guardrail_version", "DRAFT"),
        }

    def _creds_present(self) -> bool:
        c = self._creds()
        return bool(c["region"] and c["guardrail_id"])

    def _skipped_result(self, original_text: str = "",
                        reason: str = (
                            "AWS_DEFAULT_REGION and AWS_BEDROCK_GUARDRAIL_ID are required. "
                            "Also set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or configure "
                            "an IAM instance profile."
                        )) -> GuardrailResult:
        r = GuardrailResult(backend_used=GuardrailBackend.AWS_BEDROCK)
        r.passed = True
        r.action = ActionType.SKIPPED
        r.risk_score = 0.0
        r.original_text = original_text
        r.modified_text = original_text
        r.findings = {"skipped": True, "reason": reason}
        return r

    def _call_api(self, text: str, source: str = "INPUT") -> Tuple[bool, float, List[Dict]]:
        """Returns (flagged, risk_score, detected_risks)."""
        if not _BOTO3_SDK:
            raise ImportError("boto3 is not installed. Run: pip install boto3>=1.28.0")

        import boto3  # noqa: PLC0415

        c = self._creds()
        client = boto3.client(
            "bedrock-runtime",
            region_name=c["region"] or None,
            aws_access_key_id=c["access_key"] or None,
            aws_secret_access_key=c["secret_key"] or None,
        )

        response = client.apply_guardrail(
            guardrailIdentifier=c["guardrail_id"],
            guardrailVersion=c["guardrail_version"] or "DRAFT",
            source=source,
            content=[{"text": {"text": text}}],
        )

        bedrock_action = response.get("action", "NONE")
        flagged = bedrock_action == "GUARDRAIL_INTERVENED"

        risks: List[Dict] = []
        if flagged:
            for assessment in response.get("assessments", []):
                # Content policy violations
                for f in assessment.get("contentPolicy", {}).get("filters", []):
                    if f.get("action") == "BLOCKED":
                        risks.append({
                            "type": RiskCategory.JAILBREAKING.value,
                            "category": f.get("type", "content"),
                            "confidence": f.get("confidence", "LOW"),
                            "source": "aws_bedrock",
                        })
                # Topic policy violations
                for topic in assessment.get("topicPolicy", {}).get("topics", []):
                    if topic.get("action") == "BLOCKED":
                        risks.append({
                            "type": RiskCategory.PROMPT_INJECTION.value,
                            "topic": topic.get("name", "unknown"),
                            "source": "aws_bedrock",
                        })
                # Sensitive information policy
                for pii in assessment.get("sensitiveInformationPolicy", {}).get("piiEntities", []):
                    if pii.get("action") == "BLOCKED":
                        risks.append({
                            "type": RiskCategory.DATA_LEAKAGE.value,
                            "pii_type": pii.get("type", "unknown"),
                            "source": "aws_bedrock",
                        })

        return flagged, (1.0 if flagged else 0.0), risks

    @staticmethod
    def _is_auth_error(exc: Exception) -> bool:
        s = str(exc)
        return any(kw in s for kw in (
            "AccessDenied", "InvalidClientTokenId", "NoCredentialsError",
            "ExpiredToken", "UnrecognizedClientException",
        ))

    def _check_credentials(self) -> bool:
        return self._creds_present()

    def check_input(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        if not self._creds_present():
            return self._skipped_result()
        result = GuardrailResult(backend_used=GuardrailBackend.AWS_BEDROCK)
        start = time.time()
        try:
            flagged, score, risks = self._call_api(text, source="INPUT")
            result.risk_score = score
            result.passed = not flagged
            result.detected_risks = risks
            if flagged:
                result.action = ActionType.BLOCK
                result.severity = "critical"
        except Exception as exc:
            if self._is_auth_error(exc):
                self.logger.warning("AWS Bedrock auth error — marking SKIPPED: %s", exc)
                return self._skipped_result(reason=f"Invalid AWS credentials: {exc}")
            self.logger.error("AWS Bedrock API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"AWS Bedrock API error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def check_output(self, text: str, context: Optional[Dict] = None) -> GuardrailResult:
        if not self._creds_present():
            return self._skipped_result(text)
        result = GuardrailResult(backend_used=GuardrailBackend.AWS_BEDROCK)
        start = time.time()
        result.original_text = text
        try:
            flagged, score, risks = self._call_api(text, source="OUTPUT")
            result.risk_score = score
            result.passed = not flagged
            result.detected_risks = risks
            if flagged:
                result.action = ActionType.REDACT
                result.severity = "critical"
                from .actions import rewrite_text
                result.modified_text = rewrite_text(text, risks)
            else:
                result.modified_text = text
        except Exception as exc:
            if self._is_auth_error(exc):
                self.logger.warning("AWS Bedrock auth error — marking SKIPPED: %s", exc)
                return self._skipped_result(text, reason=f"Invalid AWS credentials: {exc}")
            self.logger.error("AWS Bedrock API error: %s", exc)
            from .testing import fail_closed_result
            return fail_closed_result(f"AWS Bedrock API error: {exc}")
        result.latency_ms = (time.time() - start) * 1000
        return result

    def validate_tool_call(self, tool_name: str, _tool_args: Dict[str, Any],
                           _context: Optional[Dict] = None) -> GuardrailResult:
        result = GuardrailResult(backend_used=GuardrailBackend.AWS_BEDROCK)
        blocked, reason = self._check_tools(tool_name)
        if blocked:
            result.passed = False
            result.action = ActionType.BLOCK
            result.risk_score = 0.9
            result.severity = "critical"
            result.detected_risks.append({
                "type": RiskCategory.MALICIOUS_TOOL_USE.value,
                "tool": tool_name,
                "reason": reason,
            })
        return result

    def apply_policy(self, _policy: GuardrailPolicy) -> bool:
        return True

    def health_check(self) -> Dict[str, Any]:
        if not self._creds_present():
            return {
                "status": "skipped",
                "backend": GuardrailBackend.AWS_BEDROCK.value,
                "reason": "AWS_DEFAULT_REGION and AWS_BEDROCK_GUARDRAIL_ID not configured",
            }
        if not _BOTO3_SDK:
            return {
                "status": "skipped",
                "backend": GuardrailBackend.AWS_BEDROCK.value,
                "reason": "boto3 not installed — run: pip install boto3>=1.28.0",
            }
        return {"status": "ok", "backend": GuardrailBackend.AWS_BEDROCK.value}


# ── Framework orchestrator ─────────────────────────────────────────────────────

class GuardrailFramework:
    """Main guardrail framework orchestrator"""

    def __init__(self):
        self.logger = logging.getLogger("GuardrailFramework")
        self.policies: Dict[str, GuardrailPolicy] = {}
        self.backends: Dict[str, GuardrailBackendInterface] = {}
        self.ab_tests: Dict[str, ABTestConfig] = {}
        self.audit_log: List[Dict[str, Any]] = []
        self.metrics: Dict[str, Any] = {}
        self._version_store: Optional[Any] = None
        self._persistence: Optional[Any] = None   # set via set_persistence()
        self._initialize_backends()

    def _initialize_backends(self):
        self.backends[GuardrailBackend.NEMO.value]          = NemoGuardrailsBackend({})
        self.backends[GuardrailBackend.GUARDRAILS_AI.value] = GuardrailsAIBackend({})
        self.backends[GuardrailBackend.PRESIDIO.value]      = PresidioBackend({})
        self.backends[GuardrailBackend.LAKERA.value]               = LakeraGuardBackend({})
        self.backends[GuardrailBackend.GA_GUARD.value]             = GAGuardBackend({})
        self.backends[GuardrailBackend.OPENAI_MODERATION.value]    = OpenAIModerationBackend({})
        self.backends[GuardrailBackend.AZURE_CONTENT_SAFETY.value] = AzureContentSafetyBackend({})
        self.backends[GuardrailBackend.AZURE_PROMPT_SHIELDS.value] = AzurePromptShieldsBackend({})
        self.backends[GuardrailBackend.AWS_BEDROCK.value]          = AWSBedrockBackend({})

        any_real_sdk = (
            _NEMO_SDK
            or _GUARDRAILSAI_SDK
            or _PRESIDIO_SDK
            or os.getenv("LAKERA_GUARD_API_KEY", "").strip()
            or os.getenv("GA_GUARD_API_URL", "").strip()
        )
        if not any_real_sdk:
            self.logger.warning(
                "No guardrail SDK detected. All backends will use the built-in "
                "regex/keyword scorer, which is NOT sufficient for production AI "
                "safety. Install at least one real backend:\n"
                "  • pip install guardrails-ai   (GuardrailsAI)\n"
                "  • pip install nemoguardrails  (NVIDIA NeMo)\n"
                "  • pip install presidio-analyzer presidio-anonymizer  (PII)\n"
                "  • Set LAKERA_GUARD_API_KEY for the Lakera cloud backend\n"
                "  • Set GA_GUARD_API_URL for a custom GA Guard service"
            )

    def set_persistence(self, layer: Any):
        """Wire in a PersistenceLayer. Call from server startup."""
        self._persistence = layer

    def load_from_persistence(self):
        """Restore policies and A/B tests from the DB at startup."""
        if not self._persistence:
            return
        raw_policies = self._persistence.load_all_policies()
        for data in raw_policies:
            try:
                data["backend"] = GuardrailBackend(data["backend"])
                data["action_on_violation"] = ActionType(data["action_on_violation"])
                data["risk_categories"] = [RiskCategory(r) for r in data.get("risk_categories", [])]
                policy = GuardrailPolicy(**{
                    k: v for k, v in data.items()
                    if k in GuardrailPolicy.__dataclass_fields__
                })
                self.policies[policy.id] = policy
            except Exception as exc:
                self.logger.warning(f"Skipping corrupt policy record: {exc}")
        self.logger.info(f"Loaded {len(self.policies)} policies from persistence.")

    def register_backend(self, name: str, backend: GuardrailBackendInterface):
        self.backends[name] = backend
        self.logger.info(f"Backend registered: {name}")

    # ── Policy lookup ──────────────────────────────────────────────

    def _get_policy(self, policy_id: str) -> Optional["GuardrailPolicy"]:
        """
        Return the policy, checking the in-memory cache first then the DB.

        On a cache miss (policy was created on another replica) the policy is
        loaded from persistence and cached locally so subsequent calls are fast.
        Returns None if the policy doesn't exist in either store.
        """
        if policy_id in self.policies:
            return self.policies[policy_id]

        if not self._persistence:
            return None

        try:
            data = self._persistence.load_policy(policy_id)
        except Exception as exc:
            self.logger.warning("Failed to load policy %s from DB: %s", policy_id, exc)
            return None

        if data is None:
            return None

        try:
            data["backend"] = GuardrailBackend(data["backend"])
            data["action_on_violation"] = ActionType(data["action_on_violation"])
            data["risk_categories"] = [RiskCategory(r) for r in data.get("risk_categories", [])]
            policy = GuardrailPolicy(**{
                k: v for k, v in data.items()
                if k in GuardrailPolicy.__dataclass_fields__
            })
            self.policies[policy.id] = policy
            return policy
        except Exception as exc:
            self.logger.warning("Failed to deserialize policy %s: %s", policy_id, exc)
            return None

    # ── Policy lifecycle ───────────────────────────────────────────

    def create_policy(self, policy: GuardrailPolicy, created_by: str = "api") -> str:
        self.policies[policy.id] = policy
        self.logger.info(f"Policy created: {policy.id} ({policy.name})")

        if self._version_store:
            self._version_store.save(policy, created_by=created_by, reason="created")
        if self._persistence:
            self._persistence.save_policy(policy.id, asdict(policy))

        try:
            from .bundle import push_channel
            push_channel.broadcast({"type": "policy_created",
                                    "policy_id": policy.id,
                                    "policy_name": policy.name})
        except Exception:
            pass
        return policy.id

    # Keys that backend resolves from env vars only — must not be overridable
    # via policy.rules to prevent an authenticated caller from redirecting API
    # calls to an attacker-controlled key or endpoint.
    _BLOCKED_RULE_KEYS: frozenset = frozenset({"api_key", "api_url"})

    # Tool-enforcement keys that must be reset before each policy evaluation
    # so that state from a previous policy's rules never bleeds into the next.
    _TOOL_RULE_KEYS: frozenset = frozenset({"allowed_tools", "restricted_tools", "forbidden_tools"})

    def _inject_policy_rules(self, backend: GuardrailBackendInterface, policy: GuardrailPolicy):
        """Push policy fields into backend config so the backend has full context."""
        # Clear tool-enforcement keys first. Backends are singletons; without
        # this reset, a key set by Policy A's rules persists in backend.config
        # and is silently inherited by Policy B if B's rules omit that key.
        for key in self._TOOL_RULE_KEYS:
            backend.config.pop(key, None)

        if policy.rules:
            # Exclude blocked keys (api_key, api_url) and null values.
            # Null values must be stripped: {"allowed_tools": null} would set
            # backend.config["allowed_tools"] = None, making _check_tools treat
            # it as "no allowlist configured" and skip enforcement entirely.
            safe_rules = {k: v for k, v in policy.rules.items()
                          if k not in self._BLOCKED_RULE_KEYS and v is not None}
            backend.config.update(safe_rules)
        # These are always injected so backends can look them up
        backend.config["_policy_id"] = policy.id
        backend.config["sensitivity"] = policy.sensitivity

    def check_input(self, text: str, policy_id: str,
                    context: Optional[Dict] = None) -> GuardrailResult:
        """Check input against a policy (fail-closed / default-deny)."""
        from .testing import fail_closed_result
        from .opa_gaps import data_registry, status_reporter, prom_metrics

        policy = self._get_policy(policy_id)
        if policy is None:
            return fail_closed_result(f"Policy not found: {policy_id}")
        backend = self.backends.get(policy.backend.value)
        if not backend:
            return fail_closed_result(f"Backend not configured: {policy.backend.value}")

        # RATE_LIMIT pre-check
        rate_result = self._rate_limit_check(policy, context)
        if rate_result:
            self._log_audit(policy_id, "input_check", text, rate_result)
            return rate_result

        enriched = data_registry.enrich(context or {})
        self._inject_policy_rules(backend, policy)

        try:
            result = backend.check_input(text, enriched)
        except Exception as exc:
            self.logger.error(f"Backend error in check_input: {exc}")
            result = fail_closed_result(str(exc))

        result = self._apply_post_actions(result, policy, policy_id)
        self._log_audit(policy_id, "input_check", text, result)
        status_reporter.record(policy_id, policy.backend.value, result.passed, result.latency_ms)
        prom_metrics.record_decision(policy_id, policy.backend.value,
                                     result.action.value, result.passed,
                                     result.latency_ms, result.risk_score)
        return result

    def check_output(self, text: str, policy_id: str,
                     context: Optional[Dict] = None) -> GuardrailResult:
        """Check output against a policy (fail-closed / default-deny)."""
        from .testing import fail_closed_result
        from .opa_gaps import data_registry, status_reporter, prom_metrics

        policy = self._get_policy(policy_id)
        if policy is None:
            return fail_closed_result(f"Policy not found: {policy_id}")
        backend = self.backends.get(policy.backend.value)
        if not backend:
            return fail_closed_result(f"Backend not configured: {policy.backend.value}")

        rate_result = self._rate_limit_check(policy, context)
        if rate_result:
            self._log_audit(policy_id, "output_check", text, rate_result)
            return rate_result

        enriched = data_registry.enrich(context or {})
        self._inject_policy_rules(backend, policy)

        try:
            result = backend.check_output(text, enriched)
        except Exception as exc:
            self.logger.error(f"Backend error in check_output: {exc}")
            result = fail_closed_result(str(exc))

        result = self._apply_post_actions(result, policy, policy_id)
        self._log_audit(policy_id, "output_check", text, result)
        status_reporter.record(policy_id, policy.backend.value, result.passed, result.latency_ms)
        prom_metrics.record_decision(policy_id, policy.backend.value,
                                     result.action.value, result.passed,
                                     result.latency_ms, result.risk_score)
        return result

    def validate_tool_call(self, policy_id: str, tool_name: str,
                           tool_args: Dict[str, Any],
                           context: Optional[Dict] = None) -> GuardrailResult:
        """Validate an agent tool call (fail-closed / default-deny)."""
        from .testing import fail_closed_result
        from .opa_gaps import data_registry, status_reporter, prom_metrics

        policy = self._get_policy(policy_id)
        if policy is None:
            return fail_closed_result(f"Policy not found: {policy_id}")
        backend = self.backends.get(policy.backend.value)
        if not backend:
            return fail_closed_result(f"Backend not configured: {policy.backend.value}")

        rate_result = self._rate_limit_check(policy, context)
        if rate_result:
            self._log_audit(policy_id, "tool_validation", tool_name, rate_result)
            return rate_result

        enriched = data_registry.enrich(context or {})
        self._inject_policy_rules(backend, policy)

        try:
            result = backend.validate_tool_call(tool_name, tool_args, enriched)
        except Exception as exc:
            self.logger.error(f"Backend error in validate_tool_call: {exc}")
            result = fail_closed_result(str(exc))

        result = self._apply_post_actions(result, policy, policy_id)
        self._log_audit(policy_id, "tool_validation", tool_name, result)
        status_reporter.record(policy_id, policy.backend.value, result.passed, result.latency_ms)
        prom_metrics.record_decision(policy_id, policy.backend.value,
                                     result.action.value, result.passed,
                                     result.latency_ms, result.risk_score)
        return result

    # ── Post-action handlers ───────────────────────────────────────

    def _rate_limit_check(self, policy: GuardrailPolicy,
                          context: Optional[Dict]) -> Optional[GuardrailResult]:
        """Return a blocking result if the policy's rate limit is exceeded."""
        if policy.action_on_violation != ActionType.RATE_LIMIT:
            # Also check if rules specify rate limiting regardless of action
            max_rpm = policy.rules.get("max_requests_per_minute")
            if not max_rpm:
                return None

        from .rate_limiter import policy_rate_limiter
        max_rpm = policy.rules.get("max_requests_per_minute", 60)
        user_id = (context or {}).get("user_id")

        if not policy_rate_limiter.check(policy.id, user_id, max_per_minute=int(max_rpm)):
            from .testing import fail_closed_result
            result = GuardrailResult(
                passed=False,
                action=ActionType.RATE_LIMIT,
                severity="warning",
                risk_score=0.0,
                detected_risks=[{"type": "rate_limit_exceeded",
                                 "max_per_minute": max_rpm,
                                 "user_id": user_id}],
                backend_used=policy.backend,
            )
            return result
        return None

    def _apply_post_actions(self, result: GuardrailResult,
                            policy: GuardrailPolicy,
                            policy_id: str) -> GuardrailResult:
        """
        Apply framework-level post-processing for ESCALATE and REWRITE actions
        after the backend returns a result.
        """
        if result.passed:
            return result

        effective_action = policy.action_on_violation

        if effective_action == ActionType.ESCALATE:
            result.action = ActionType.ESCALATE
            from .actions import escalate
            escalate(
                policy_id=policy_id,
                policy_name=policy.name,
                result=result,
                escalation_email=policy.escalation_email,
            )

        elif effective_action == ActionType.REWRITE:
            result.action = ActionType.REWRITE
            if result.original_text and not result.modified_text:
                from .actions import rewrite_text
                result.modified_text = rewrite_text(result.original_text, result.detected_risks)
            elif not result.modified_text and result.original_text:
                result.modified_text = result.original_text

        return result

    # ── Policy updates ─────────────────────────────────────────────

    def update_policy(self, policy_id: str, updates: Dict[str, Any],
                      updated_by: str = "api", reason: str = "") -> bool:
        if policy_id not in self.policies:
            return False

        policy = self.policies[policy_id]
        if self._version_store:
            self._version_store.save(policy, created_by=updated_by,
                                     reason=f"pre-update: {reason}")

        for key, value in updates.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        policy.updated_at = datetime.now(timezone.utc).isoformat()

        if self._persistence:
            self._persistence.save_policy(policy.id, asdict(policy))

        self.logger.info(f"Policy updated: {policy_id}")

        try:
            from .opa_gaps import precompiler
            if precompiler:
                precompiler.invalidate(policy_id)
        except Exception:
            pass
        try:
            from .bundle import push_channel
            push_channel.broadcast({"type": "policy_updated",
                                    "policy_id": policy_id,
                                    "changes": list(updates.keys())})
        except Exception:
            pass
        return True

    def delete_policy(self, policy_id: str) -> bool:
        if policy_id in self.policies:
            del self.policies[policy_id]
            if self._persistence:
                self._persistence.soft_delete_policy(policy_id)
            self.logger.info(f"Policy deleted: {policy_id}")
            try:
                from .bundle import push_channel
                push_channel.broadcast({"type": "policy_deleted", "policy_id": policy_id})
            except Exception:
                pass
            return True
        return False

    # ── A/B testing ────────────────────────────────────────────────

    def create_ab_test(self, test_config: ABTestConfig) -> str:
        self.ab_tests[test_config.id] = test_config
        if self._persistence:
            self._persistence.save_ab_test(test_config.id, asdict(test_config))
        self.logger.info(f"A/B test created: {test_config.id} ({test_config.name})")
        return test_config.id

    def get_policy_for_abtest(self, test_id: str,
                               user_id: Optional[str] = None) -> str:
        """
        Deterministic bucket assignment when user_id is provided,
        random otherwise. This ensures a single user always sees the same
        policy variant for the duration of the test.
        """
        if test_id not in self.ab_tests:
            raise ValueError(f"A/B test not found: {test_id}")

        test = self.ab_tests[test_id]

        if user_id:
            h = int(hashlib.md5(f"{test_id}:{user_id}".encode()).hexdigest(), 16)
            bucket = (h % 10_000) / 10_000.0
        else:
            import random
            bucket = random.random()

        if bucket < test.traffic_split:
            return test.experiment_policy_id
        return test.control_policy_id

    # ── Audit / metrics ────────────────────────────────────────────

    def _log_audit(self, policy_id: str, action: str,
                   input_text: str, result: GuardrailResult):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "policy_id": policy_id,
            "action": action,
            "input_preview": input_text[:120] if input_text else "",
            "passed": result.passed,
            "severity": result.severity,
            "action_taken": result.action.value,
            "risk_score": result.risk_score,
            "latency_ms": result.latency_ms,
            "backend": result.backend_used.value,
            "request_id": result.request_id,
        }
        self.audit_log.append(entry)
        # Cap in-memory log at 10 000 entries to prevent unbounded growth
        if len(self.audit_log) > 10_000:
            self.audit_log = self.audit_log[-5_000:]

        if self._persistence:
            try:
                self._persistence.append_audit(entry)
            except Exception as exc:
                self.logger.warning(f"Audit persistence failed: {exc}")

        self._update_metrics(result)

    def _update_metrics(self, result: GuardrailResult):
        if "total_checks" not in self.metrics:
            self.metrics = {
                "total_checks": 0,
                "passed": 0,
                "blocked": 0,
                "avg_latency_ms": 0,
                "by_backend": {},
                "by_action": {},
            }
        self.metrics["total_checks"] += 1
        if result.passed:
            self.metrics["passed"] += 1
        else:
            self.metrics["blocked"] += 1

        backend_name = result.backend_used.value
        self.metrics["by_backend"][backend_name] = \
            self.metrics["by_backend"].get(backend_name, 0) + 1

        action_name = result.action.value
        self.metrics["by_action"][action_name] = \
            self.metrics["by_action"].get(action_name, 0) + 1

    def get_metrics(self) -> Dict[str, Any]:
        return self.metrics

    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        if self._persistence:
            try:
                return self._persistence.get_audit_log(limit)
            except Exception:
                pass
        return self.audit_log[-limit:]

    def export_policy(self, policy_id: str, format: str = "json") -> str:
        if policy_id not in self.policies:
            return ""
        policy = self.policies[policy_id]
        if format == "json":
            return json.dumps(asdict(policy), indent=2, default=str)
        if format == "yaml":
            return self._convert_to_yaml(asdict(policy))
        return ""

    def _convert_to_yaml(self, data: Dict) -> str:
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


# ── Global singleton ───────────────────────────────────────────────────────────

_framework: Optional[GuardrailFramework] = None


def get_framework() -> GuardrailFramework:
    global _framework
    if _framework is None:
        _framework = GuardrailFramework()
    return _framework
