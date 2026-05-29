"""
Guardrail Framework Abstraction Layer
Unified interface for AI safety guardrails across multiple backends
"""

__version__ = "1.0.0"
__author__ = "Enterprise AI Safety Team"

# Core exports
from .core import (
    GuardrailFramework,
    GuardrailPolicy,
    GuardrailBackend,
    GuardrailResult,
    RiskCategory,
    ActionType,
    ABTestConfig,
    GuardrailBackendInterface,
    NemoGuardrailsBackend,
    GuardrailsAIBackend,
    PresidioBackend,
    get_framework,
)

# Compiler exports
from .compiler import (
    PolicyCompiler,
    UnifiedPolicyBuilder,
    PolicyTemplates,
)

# Observability exports
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

# Convenience function to initialize everything
def initialize(config: dict = None):
    """
    Initialize the guardrail framework with optional configuration
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        GuardrailFramework instance with observability stack
    """
    framework = get_framework()
    observability = ObservabilityStack()
    
    return {
        "framework": framework,
        "observability": observability,
        "compiler": PolicyCompiler(),
    }


__all__ = [
    # Core
    "GuardrailFramework",
    "GuardrailPolicy",
    "GuardrailBackend",
    "GuardrailResult",
    "RiskCategory",
    "ActionType",
    "ABTestConfig",
    "GuardrailBackendInterface",
    "NemoGuardrailsBackend",
    "GuardrailsAIBackend",
    "PresidioBackend",
    "get_framework",
    
    # Compiler
    "PolicyCompiler",
    "UnifiedPolicyBuilder",
    "PolicyTemplates",
    
    # Observability
    "MetricsCollector",
    "AlertingSystem",
    "Alert",
    "AlertSeverity",
    "AlertType",
    "AuditLogger",
    "PerformanceMonitor",
    "ObservabilityStack",
    
    # Helpers
    "initialize",
]

# ── OPA gap implementations ──────────────────────────────────
from .testing import (
    PolicyTestCase,
    PolicyTestRunner,
    TestResult,
    TestSuiteReport,
    fail_closed_result,
)
from .decision_log import (
    DecisionEvent,
    DecisionLogShipper,
)
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
