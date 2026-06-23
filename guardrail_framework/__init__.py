"""
Guardrail Framework Abstraction Layer
Unified interface for AI safety guardrails across multiple backends
"""

from typing import Optional

__version__ = "1.0.0"
__author__ = "Enterprise AI Safety Team"

# ── Core ──────────────────────────────────────────────────────────────────────
from .core import (
    GuardrailFramework,
    GuardrailPolicy,
    GuardrailBackend,
    GuardrailResult,
    RiskCategory,
    ActionType,
    ABTestConfig,
    GuardrailBackendInterface,
    # Backend implementations — all inherit GuardrailBackendInterface
    NemoGuardrailsBackend,
    GuardrailsAIBackend,
    PresidioBackend,
    LakeraGuardBackend,
    GAGuardBackend,
    OpenAIModerationBackend,
    AzureContentSafetyBackend,
    AzurePromptShieldsBackend,
    AWSBedrockBackend,
    LlamaFirewallBackend,
    LLMGuardBackend,
    get_framework,
)

# ── Auth / persistence / rate-limiting ────────────────────────────────────────
from .auth import APIKeyMiddleware, load_api_keys
from .persistence import PersistenceLayer
from .rate_limiter import PolicyRateLimiter, policy_rate_limiter

# ── Compiler / policy builder / templates ─────────────────────────────────────
from .compiler import (
    PolicyCompiler,
    UnifiedPolicyBuilder,
    PolicyTemplates,
)

# ── Observability ─────────────────────────────────────────────────────────────
from .observability import (
    MetricsCollector,
    AlertingSystem,
    Alert,
    AlertSeverity,
    AlertType,
    AuditLogger,
    PerformanceMonitor,
    ObservabilityStack,
)

# ── Testing / policy validation ───────────────────────────────────────────────
from .testing import (
    PolicyTestCase,
    PolicyTestRunner,
    TestResult,
    TestSuiteReport,
    fail_closed_result,
)

# ── Decision logging ──────────────────────────────────────────────────────────
from .decision_log import (
    DecisionEvent,
    DecisionLogShipper,
)

# ── Bundle distribution / versioning ─────────────────────────────────────────
from .bundle import (
    BundleBuilder,
    BundleLoader,
    BundlePoller,
    BundleMetadata,
    PolicyVersionStore,
    PolicySnapshot,
    PolicyPushChannel,
    push_channel,
)

# ── OPA gap implementations ───────────────────────────────────────────────────
from .opa_gaps import (
    PolicyPrecompiler,
    ResidualQuery,
    PrometheusMetrics,
    StatusReporter,
    PolicyStatus,
    WasmReadyScorer,
    DataProvider,
    StaticBlocklistProvider,
    HttpDataProvider,
    DataProviderRegistry,
    prom_metrics,
    status_reporter,
    data_registry,
    wasm_scorer,
)


def initialize(_config: Optional[dict] = None) -> dict:
    """Initialize the guardrail framework.

    Returns a dict with ``framework``, ``observability``, and ``compiler``
    keys, all wired together and ready to use.
    """
    framework = get_framework()
    observability = ObservabilityStack()
    return {
        "framework": framework,
        "observability": observability,
        "compiler": PolicyCompiler(),
    }


__all__ = [
    # ── Core ──────────────────────────────────────────────────────────────
    "GuardrailFramework",
    "GuardrailPolicy",
    "GuardrailBackend",
    "GuardrailResult",
    "RiskCategory",
    "ActionType",
    "ABTestConfig",
    "GuardrailBackendInterface",
    # Backends (local / free)
    "NemoGuardrailsBackend",
    "GuardrailsAIBackend",
    "PresidioBackend",
    "LlamaFirewallBackend",
    "LLMGuardBackend",
    # Backends (cloud API key required)
    "LakeraGuardBackend",
    "GAGuardBackend",
    "OpenAIModerationBackend",
    "AzureContentSafetyBackend",
    "AzurePromptShieldsBackend",
    "AWSBedrockBackend",
    "get_framework",

    # ── Auth / persistence / rate-limiting ────────────────────────────────
    "APIKeyMiddleware",
    "load_api_keys",
    "PersistenceLayer",
    "PolicyRateLimiter",
    "policy_rate_limiter",

    # ── Compiler / policy builder / templates ─────────────────────────────
    "PolicyCompiler",
    "UnifiedPolicyBuilder",
    "PolicyTemplates",

    # ── Observability ─────────────────────────────────────────────────────
    "MetricsCollector",
    "AlertingSystem",
    "Alert",
    "AlertSeverity",
    "AlertType",
    "AuditLogger",
    "PerformanceMonitor",
    "ObservabilityStack",

    # ── Testing / policy validation ───────────────────────────────────────
    "PolicyTestCase",
    "PolicyTestRunner",
    "TestResult",
    "TestSuiteReport",
    "fail_closed_result",

    # ── Decision logging ──────────────────────────────────────────────────
    "DecisionEvent",
    "DecisionLogShipper",

    # ── Bundle distribution / versioning ──────────────────────────────────
    "BundleBuilder",
    "BundleLoader",
    "BundlePoller",
    "BundleMetadata",
    "PolicyVersionStore",
    "PolicySnapshot",
    "PolicyPushChannel",
    "push_channel",

    # ── OPA gap implementations ───────────────────────────────────────────
    "PolicyPrecompiler",
    "ResidualQuery",
    "PrometheusMetrics",
    "StatusReporter",
    "PolicyStatus",
    "WasmReadyScorer",
    "DataProvider",
    "StaticBlocklistProvider",
    "HttpDataProvider",
    "DataProviderRegistry",
    "prom_metrics",
    "status_reporter",
    "data_registry",
    "wasm_scorer",

    # ── Helpers ───────────────────────────────────────────────────────────
    "initialize",
]
