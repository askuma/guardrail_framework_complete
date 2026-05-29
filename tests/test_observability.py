import pytest
import time
from datetime import datetime
from guardrail_framework.observability import (
    MetricsCollector, AlertingSystem, AlertSeverity, 
    ObservabilityStack, PerformanceMonitor, AuditLogger
)

def test_metrics_collector():
    collector = MetricsCollector(retention_hours=24)
    
    collector.record_metric("latency_ms", 50.0)
    collector.record_metric("latency_ms", 100.0)
    collector.record_metric("latency_ms", 75.0)
    
    summary = collector.get_metric_summary("latency_ms")
    assert summary["count"] == 3
    assert summary["min"] == 50.0
    assert summary["max"] == 100.0
    assert summary["avg"] == 75.0
    assert summary["latest"] == 75.0
    
    # Test empty metric
    empty_summary = collector.get_metric_summary("non_existent")
    assert empty_summary == {}

def test_alerting_system():
    metrics = MetricsCollector()
    alerting = AlertingSystem(metrics)
    
    # Trigger high block rate (threshold 0.3)
    metrics.record_metric("block_rate", 0.5)
    
    alerts = alerting.check_alerts()
    assert len(alerts) == 1
    assert alerts[0].alert_type == "high_block_rate"
    assert alerts[0].severity == AlertSeverity.WARNING
    assert alerts[0].metric_value == 0.5
    
    alerting.trigger_alert(alerts[0])
    active = alerting.get_active_alerts()
    assert len(active) == 1
    
    # Resolve alert
    alerting.resolve_alert(active[0].id)
    assert len(alerting.get_active_alerts()) == 0

def test_performance_monitor():
    monitor = PerformanceMonitor()
    monitor.sla_targets["latency_p95_ms"] = 100
    
    # Insert latencies below threshold
    for i in range(100):
        monitor.record_check("test_backend", latency_ms=50.0, passed=True)
        
    sla = monitor.get_sla_compliance("test_backend")
    assert sla["p95_latency_ms"] == 50.0
    assert sla["sla_met"] == True
    
    health = monitor.get_backend_health("test_backend")
    assert health["status"] == "healthy"

    # Insert latencies above threshold
    for i in range(100):
        monitor.record_check("test_backend", latency_ms=200.0, passed=True)
        
    sla2 = monitor.get_sla_compliance("test_backend")
    assert sla2["p95_latency_ms"] == 200.0
    assert sla2["sla_met"] == False
    
    health2 = monitor.get_backend_health("test_backend")
    assert health2["status"] == "degraded"

def test_audit_logger():
    audit = AuditLogger()
    audit.log_guardrail_check(
        policy_id="test_id", action="check", passed=True, 
        risk_score=0.1, input_text="hello", output_text="world",
        backend="test_backend", latency_ms=10.0
    )
    
    assert len(audit.entries) == 1
    entry = audit.entries[0]
    assert entry["policy_id"] == "test_id"
    assert entry["passed"] == True
    assert entry["input_length"] == 5
    
    # Test date range filtering - ensure we generate proper start/end timestamps
    start_date = "2020-01-01T00:00:00"
    end_date = "2030-01-01T00:00:00"
    
    report = audit.get_compliance_report(start_date, end_date)
    assert report["summary"]["checks_passed"] == 1
    assert report["summary"]["total_checks"] == 1

def test_observability_stack():
    stack = ObservabilityStack()
    
    stack.record_guardrail_check(
        policy_id="pol1", backend="guardrails_ai",
        input_text="hello", output_text="world",
        passed=False, risk_score=0.9, latency_ms=150.0
    )
    
    dashboard = stack.get_dashboard_data()
    assert dashboard["metrics"]["check_count"]["latest"] == 1
    assert dashboard["metrics"]["pass_rate"]["latest"] == 0.0
    assert dashboard["metrics"]["risk_score"]["latest"] == 0.9
    assert dashboard["metrics"]["latency_ms"]["latest"] == 150.0
