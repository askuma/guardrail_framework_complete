"""
Red-team runner for the Guardrail Framework.

Fires AttackProbes from probes.py against one or more backends, collects
structured reports, and detects regressions between runs.

Usage::

    from guardrail_framework.red_team_runner import RedTeamRunner
    from guardrail_framework.probes import ProbeLibrary, AttackCategory
    from guardrail_framework.core import get_framework, GuardrailBackend

    runner = RedTeamRunner(get_framework())

    # Single-backend sweep
    report = runner.run_against_backend(
        GuardrailBackend.GUARDRAILS_AI,
        categories=[AttackCategory.PROMPT_INJECTION],
        severity_filter="critical",
    )
    print(f"Pass rate: {report.pass_rate:.1%}")

    # Multi-backend comparison
    cmp = runner.compare_backends(
        [GuardrailBackend.GUARDRAILS_AI, GuardrailBackend.NEMO],
    )
    print(cmp.best_overall, cmp.category_winners)

    # Regression detection
    diff = runner.run_regression(
        baseline_report_id=report.run_id,
        backend=GuardrailBackend.GUARDRAILS_AI,
    )
    for reg in diff["regressions"]:   # RED  — was passing, now failing
        print("[RED] regression:", reg["probe_id"], reg["description"])
    for imp in diff["improvements"]:  # GREEN — was failing, now passing
        print("[GREEN] improvement:", imp["probe_id"])
"""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as _FuturesTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

_BACKEND_TIMEOUT_SECS = 120

from .core import (
    ActionType,
    GuardrailBackend,
    GuardrailFramework,
    GuardrailPolicy,
    GuardrailResult,
    RiskCategory,
)
from .decision_log import DecisionEvent, DecisionLogShipper
from .probes import AttackCategory, AttackProbe, ProbeLibrary

logger = logging.getLogger("RedTeamRunner")

# Minimum % of probes that must have run for a backend to be eligible for
# Best/Worst labels.  Backends below this threshold ran too few probes
# (e.g. due to quota exhaustion) to produce a meaningful overall score.
MIN_COVERAGE_PCT: float = 50.0

# Static backend scope metadata.
# "type": "general"     — designed to catch broad LLM attack categories.
# "type": "specialized" — purpose-built for a specific use case or category.
# Used to gate Best/Worst badges and drive scope annotations in the UI.
BACKEND_SCOPE: Dict[str, Dict[str, Any]] = {
    "nemo": {
        "type": "general",
        "label": "General LLM Safety",
    },
    "guardrails_ai": {
        "type": "specialized",
        "label": "Validation Framework",
        "note": "requires validators; compare within PII/content use cases",
    },
    "presidio": {
        "type": "specialized",
        "label": "PII Detection",
        "note": "designed for PII and credential detection (LLM06) only",
    },
    "lakera": {
        "type": "general",
        "label": "Prompt Security",
    },
    "ga_guard": {
        # When GA_GUARD_API_URL is set this is a real external guardrail API
        # (general-purpose).  Without it the backend runs the local wasm scorer
        # which is too limited to rank alongside real guardrails — server.py
        # overrides this to type "specialized" at compare time in that case.
        "type": "general",
        "label": "Content Safety",
    },
    "openai_moderation": {
        "type": "specialized",
        "label": "Content Moderation",
        "note": "content policy classification only; subject to rate limits",
    },
    "azure_content_safety": {
        "type": "general",
        "label": "Content Safety",
    },
    "azure_prompt_shields": {
        "type": "specialized",
        "label": "Prompt Injection Guard",
        "note": "designed specifically for prompt injection detection",
    },
    "aws_bedrock": {
        "type": "general",
        "label": "General Guardrails",
    },
}


# ── Result dataclasses ────────────────────────────────────────────────────────


@dataclass
class ProbeResult:
    """Outcome of firing a single AttackProbe against one backend."""

    probe: AttackProbe
    backend: GuardrailBackend
    actual_action: Optional[ActionType]   # None when preflight credential check failed
    expected_action: ActionType
    passed: Optional[bool]                # None when preflight credential check failed
    latency_ms: float
    timestamp: str
    raw_response: GuardrailResult
    skipped: bool = False                 # True when backend returned SKIPPED or creds missing
    skip_reason: str = ""                 # "MISSING_CREDENTIALS" or empty


@dataclass
class RedTeamReport:
    """Aggregated result of running a probe set against a single backend.

    Fields
    ------
    backend             Backend that was tested.
    run_id              UUID that indexes this report in RedTeamRunner._reports.
    timestamp           ISO-8601 UTC start time of the run.
    total_probes        Number of probes fired.
    passed              Probes where actual_action matched expected_action.
    failed              Probes where they did not match.
    pass_rate           passed / total_probes, rounded to 4 dp.
    results_by_category OWASP ref → {total, passed, failed, pass_rate}.
    results_by_severity severity  → {total, passed, failed, pass_rate}.
    average_latency_ms  Mean end-to-end latency across all probes.
    probe_results       Full per-probe details; required for regression comparison.
    """

    backend: GuardrailBackend
    run_id: str
    timestamp: str
    total_probes: int       # active (non-skipped) probes only
    passed: int
    failed: int
    pass_rate: float
    results_by_category: Dict[str, Dict[str, Any]]
    results_by_severity: Dict[str, Dict[str, Any]]
    average_latency_ms: float
    probe_results: List[ProbeResult] = field(default_factory=list)
    skipped_count: int = 0  # probes excluded because backend returned SKIPPED
    skipped_backends: Dict[str, str] = field(default_factory=dict)  # backend → reason
    coverage_pct: float = 0.0  # (total_probes / all attempted) * 100


@dataclass
class ComparisonReport:
    """Side-by-side comparison of multiple backends on the same probe set.

    Fields
    ------
    run_id              UUID for this comparison run.
    timestamp           ISO-8601 UTC start time.
    backends_tested     Ordered list of backends that were evaluated.
    reports             backend.value → RedTeamReport for each backend.
    best_overall        backend.value with the highest overall pass_rate.
    worst_overall       backend.value with the lowest overall pass_rate.
    category_winners    OWASP ref → backend.value that scored highest per category.
    summary_table       Flat list of dicts, one row per (backend × category),
                        ready for direct dashboard / table rendering.
    """

    run_id: str
    timestamp: str
    backends_tested: List[GuardrailBackend]
    reports: Dict[str, RedTeamReport]
    best_overall: str
    worst_overall: str
    category_winners: Dict[str, str]
    summary_table: List[Dict[str, Any]]
    skipped_backends: Dict[str, str] = field(default_factory=dict)  # backend → reason


# ── Runner ────────────────────────────────────────────────────────────────────


class RedTeamRunner:
    """
    Orchestrates red-team probing of guardrail backends.

    Parameters
    ----------
    framework:
        Live ``GuardrailFramework`` instance to probe against.  The runner
        injects ephemeral policies directly into ``framework.policies`` for
        the duration of each run and removes them in a ``finally`` block, so
        the normal audit/persistence/broadcast paths are not triggered for
        internal bookkeeping policies.
    audit_shipper:
        Optional ``DecisionLogShipper`` (from decision_log.py).  When
        provided, every probe result is enqueued as a ``DecisionEvent`` on
        the audit trail.  When ``None`` the framework's built-in
        ``_log_audit`` path (already called by ``check_input``) is the only
        audit record.
    default_sensitivity:
        Sensitivity level injected into each ephemeral policy.  ``"high"``
        maximises detection coverage at the cost of more false-positives.
    """

    def __init__(
        self,
        framework: GuardrailFramework,
        audit_shipper: Optional[DecisionLogShipper] = None,
        default_sensitivity: str = "high",
    ) -> None:
        self._framework = framework
        self._shipper = audit_shipper
        self._sensitivity = default_sensitivity

        # In-memory stores keyed by run_id — same pattern as server.py state.
        self._reports: Dict[str, RedTeamReport] = {}
        self._comparison_reports: Dict[str, ComparisonReport] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def run_against_backend(
        self,
        backend: GuardrailBackend,
        probes: Optional[List[AttackProbe]] = None,
        categories: Optional[List[AttackCategory]] = None,
        severity_filter: Optional[str] = None,
    ) -> RedTeamReport:
        """Fire a filtered probe set against *backend* and return a report.

        Parameters
        ----------
        backend:
            The backend under test.
        probes:
            Explicit probe list.  Defaults to all built-in ``ProbeLibrary``
            probes when omitted.
        categories:
            When supplied, only probes whose ``category`` is in this list run.
        severity_filter:
            When supplied (``"low"`` | ``"medium"`` | ``"high"`` |
            ``"critical"``), only probes of that severity run.

        Returns
        -------
        RedTeamReport stored in ``self._reports[run_id]`` before being returned.
        """
        run_id = str(uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        active_probes = _filter_probes(probes, categories, severity_filter)

        # Pre-flight credential check — skip all probes if credentials absent.
        backend_adapter = self._framework.backends.get(backend.value)
        if backend_adapter is not None and not backend_adapter._check_credentials():
            skip_reason = "MISSING_CREDENTIALS"
            now = datetime.now(timezone.utc).isoformat()
            probe_results = [
                ProbeResult(
                    probe=probe,
                    backend=backend,
                    actual_action=None,
                    expected_action=probe.expected_action,
                    passed=None,
                    latency_ms=0.0,
                    timestamp=now,
                    raw_response=GuardrailResult(
                        backend_used=backend,
                        action=ActionType.SKIPPED,
                        findings={"skipped": True, "reason": skip_reason},
                    ),
                    skipped=True,
                    skip_reason=skip_reason,
                )
                for probe in active_probes
            ]
            report = _build_report(
                backend, run_id, timestamp, probe_results,
                skipped_backends={backend.value: skip_reason},
            )
            self._reports[run_id] = report
            logger.info(
                "Red-team run %s SKIPPED | backend=%s | reason=%s",
                run_id, backend.value, skip_reason,
            )
            return report

        logger.info(
            "Red-team run %s starting | backend=%s | probes=%d",
            run_id, backend.value, len(active_probes),
        )

        # Register an ephemeral policy directly in the in-memory dict so that
        # framework.check_input() can find it via _get_policy().  This avoids
        # writing a throwaway row to the DB and skips SSE broadcasts.
        policy = GuardrailPolicy(
            name=f"__red_team_{run_id}",
            backend=backend,
            risk_categories=list(RiskCategory),
            sensitivity=self._sensitivity,
            action_on_violation=ActionType.BLOCK,
        )
        self._framework.policies[policy.id] = policy

        try:
            probe_results = [
                self._run_one(probe, policy.id, backend)
                for probe in active_probes
            ]
        finally:
            # Always evict the ephemeral policy — this runs even if a probe
            # raises so the registry never accumulates stale entries.
            self._framework.policies.pop(policy.id, None)

        report = _build_report(backend, run_id, timestamp, probe_results)
        self._reports[run_id] = report

        logger.info(
            "Red-team run %s complete | pass_rate=%.1f%% (%d/%d) | "
            "avg_latency=%.1f ms",
            run_id,
            report.pass_rate * 100,
            report.passed,
            report.total_probes,
            report.average_latency_ms,
        )
        return report

    def compare_backends(
        self,
        backends: List[GuardrailBackend],
        probes: Optional[List[AttackProbe]] = None,
        categories: Optional[List[AttackCategory]] = None,
    ) -> ComparisonReport:
        """Run the same probe set against every backend and compare results.

        Each backend gets its own ``run_against_backend`` call (and therefore
        its own entry in ``self._reports``).

        Returns
        -------
        ComparisonReport stored in ``self._comparison_reports[run_id]``.

        Raises
        ------
        ValueError if *backends* is empty.
        """
        if not backends:
            raise ValueError("backends must contain at least one GuardrailBackend.")

        run_id = str(uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        active_probes = probes or []

        def _run(backend: GuardrailBackend) -> RedTeamReport:
            return self.run_against_backend(backend, probes=probes, categories=categories)

        reports: Dict[str, RedTeamReport] = {}
        with ThreadPoolExecutor(max_workers=len(backends)) as pool:
            futures: Dict[str, Future] = {
                b.value: pool.submit(_run, b) for b in backends
            }
            for bval, fut in futures.items():
                try:
                    reports[bval] = fut.result(timeout=_BACKEND_TIMEOUT_SECS)
                except _FuturesTimeout:
                    logger.warning("Backend %s timed out after %ds — marking SKIPPED", bval, _BACKEND_TIMEOUT_SECS)
                    reports[bval] = _build_timeout_report(
                        GuardrailBackend(bval), active_probes, timestamp
                    )
                except Exception as exc:
                    logger.error("Backend %s raised %s — marking SKIPPED", bval, exc)
                    reports[bval] = _build_timeout_report(
                        GuardrailBackend(bval), active_probes, timestamp, reason=str(exc)
                    )

        # Best/Worst: require general-purpose type AND minimum probe coverage.
        # Specialized tools (Presidio, GuardrailsAI, etc.) and backends that hit
        # quota/rate-limits mid-run are excluded from this ranking so the badge
        # reflects real general security coverage, not an artifact of scope or limits.
        # GA Guard is also excluded when running without GA_GUARD_API_URL because
        # it falls back to the local wasm scorer, not a real external guardrail API.
        ga_guard_wasm_mode = not os.getenv("GA_GUARD_API_URL", "").strip()
        eligible = {
            k: v for k, v in reports.items()
            if v.total_probes > 0
            and v.coverage_pct >= MIN_COVERAGE_PCT
            and BACKEND_SCOPE.get(k, {}).get("type") == "general"
            and not (k == "ga_guard" and ga_guard_wasm_mode)
        }
        # Fallback: if no general backend met the coverage threshold, rank all
        # non-empty reports so the field is never empty.
        ranked = eligible or {k: v for k, v in reports.items() if v.total_probes > 0} or reports
        best_overall = max(ranked, key=lambda k: ranked[k].pass_rate)
        worst_overall = min(ranked, key=lambda k: ranked[k].pass_rate)

        all_skipped: Dict[str, str] = {}
        for r in reports.values():
            all_skipped.update(r.skipped_backends)

        comparison = ComparisonReport(
            run_id=run_id,
            timestamp=timestamp,
            backends_tested=list(backends),
            reports=reports,
            best_overall=best_overall,
            worst_overall=worst_overall,
            category_winners=_compute_category_winners(reports),
            summary_table=_build_summary_table(reports),
            skipped_backends=all_skipped,
        )
        self._comparison_reports[run_id] = comparison
        return comparison

    def run_regression(
        self,
        baseline_report_id: str,
        backend: GuardrailBackend,
        probes: Optional[List[AttackProbe]] = None,
        categories: Optional[List[AttackCategory]] = None,
        severity_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compare a fresh run against a stored baseline report.

        Probes present in both runs are compared at the probe-id level:

        * **Regression (RED)** — probe was passing in the baseline but fails
          now.  These appear in ``result["regressions"]``.
        * **Improvement (GREEN)** — probe was failing in the baseline but
          passes now.  These appear in ``result["improvements"]``.

        Probes that exist only in one run (e.g. newly added probes) are
        silently skipped; only the intersection of probe IDs is compared.

        Parameters
        ----------
        baseline_report_id:
            The ``run_id`` of a previously stored ``RedTeamReport``.
        backend:
            Backend to sweep in the current run.

        Returns
        -------
        dict with keys: ``run_id``, ``baseline_run_id``, ``backend``,
        ``regressions``, ``improvements``, ``stable_pass``, ``stable_fail``,
        ``total_compared``, ``current_pass_rate``, ``baseline_pass_rate``,
        ``delta_pass_rate``.

        Raises
        ------
        KeyError if *baseline_report_id* is not in ``self._reports``.
        """
        if baseline_report_id not in self._reports:
            raise KeyError(
                f"No stored report with run_id={baseline_report_id!r}. "
                f"Known IDs: {list(self._reports)}"
            )

        baseline = self._reports[baseline_report_id]
        current = self.run_against_backend(
            backend,
            probes=probes,
            categories=categories,
            severity_filter=severity_filter,
        )

        baseline_by_id: Dict[str, ProbeResult] = {
            pr.probe.id: pr for pr in baseline.probe_results
        }
        current_by_id: Dict[str, ProbeResult] = {
            pr.probe.id: pr for pr in current.probe_results
        }

        regressions: List[Dict[str, Any]] = []
        improvements: List[Dict[str, Any]] = []
        stable_pass = 0
        stable_fail = 0

        shared_ids: Set[str] = set(baseline_by_id) & set(current_by_id)
        for probe_id in sorted(shared_ids):
            b = baseline_by_id[probe_id]
            c = current_by_id[probe_id]

            if b.passed and not c.passed:
                regressions.append(_diff_row(b, c, flag="RED"))
            elif not b.passed and c.passed:
                improvements.append(_diff_row(b, c, flag="GREEN"))
            elif c.passed:
                stable_pass += 1
            else:
                stable_fail += 1

        delta = current.pass_rate - baseline.pass_rate
        return {
            "run_id": current.run_id,
            "baseline_run_id": baseline_report_id,
            "backend": backend.value,
            "regressions": regressions,
            "improvements": improvements,
            "stable_pass": stable_pass,
            "stable_fail": stable_fail,
            "total_compared": len(shared_ids),
            "current_pass_rate": current.pass_rate,
            "baseline_pass_rate": baseline.pass_rate,
            "delta_pass_rate": round(delta, 4),
        }

    # ── Report accessors ──────────────────────────────────────────────────────

    def get_report(self, run_id: str) -> Optional[RedTeamReport]:
        """Return a stored ``RedTeamReport`` by run_id, or ``None``."""
        return self._reports.get(run_id)

    def get_comparison_report(self, run_id: str) -> Optional[ComparisonReport]:
        """Return a stored ``ComparisonReport`` by run_id, or ``None``."""
        return self._comparison_reports.get(run_id)

    def list_reports(self) -> List[Dict[str, Any]]:
        """Lightweight index of every stored report (no probe-level detail)."""
        return [
            {
                "run_id": r.run_id,
                "backend": r.backend.value,
                "timestamp": r.timestamp,
                "total_probes": r.total_probes,
                "passed": r.passed,
                "failed": r.failed,
                "pass_rate": r.pass_rate,
                "average_latency_ms": r.average_latency_ms,
            }
            for r in self._reports.values()
        ]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run_one(
        self,
        probe: AttackProbe,
        policy_id: str,
        backend: GuardrailBackend,
    ) -> ProbeResult:
        """Fire a single probe through ``framework.check_input`` and record it."""
        t0 = time.perf_counter()
        try:
            result: GuardrailResult = self._framework.check_input(
                probe.payload,
                policy_id,
                context={"red_team": True, "probe_id": probe.id},
            )
        except Exception as exc:
            logger.warning("Probe %s raised %s: %s", probe.id, type(exc).__name__, exc)
            from .testing import fail_closed_result
            result = fail_closed_result(str(exc))

        # Use end-to-end wall-clock latency so framework overhead is included.
        latency_ms = (time.perf_counter() - t0) * 1_000.0
        result.latency_ms = latency_ms

        actual_action = result.action
        is_skipped = actual_action == ActionType.SKIPPED
        passed = (not is_skipped) and (actual_action == probe.expected_action)

        if self._shipper is not None:
            self._shipper.enqueue(
                DecisionEvent(
                    policy_id=policy_id,
                    policy_name=f"red_team_{probe.id}",
                    backend=backend.value,
                    check_type="red_team_probe",
                    input_length=len(probe.payload),
                    passed=passed,
                    risk_score=result.risk_score,
                    action_taken=actual_action.value,
                    severity=probe.severity,
                    detected_risks=result.detected_risks,
                    latency_ms=latency_ms,
                    user_context={
                        "probe_id": probe.id,
                        "owasp_ref": probe.owasp_ref,
                        "category": probe.category.value,
                        "tags": probe.tags,
                    },
                )
            )

        return ProbeResult(
            probe=probe,
            backend=backend,
            actual_action=actual_action,
            expected_action=probe.expected_action,
            passed=passed,
            latency_ms=round(latency_ms, 2),
            timestamp=datetime.now(timezone.utc).isoformat(),
            raw_response=result,
            skipped=is_skipped,
        )


# ── Module-level helpers (pure functions, no framework dependency) ─────────────


def _filter_probes(
    probes: Optional[List[AttackProbe]],
    categories: Optional[List[AttackCategory]],
    severity_filter: Optional[str],
) -> List[AttackProbe]:
    active = list(probes) if probes is not None else ProbeLibrary().all_probes()
    if categories:
        cat_set = set(categories)
        active = [p for p in active if p.category in cat_set]
    if severity_filter:
        active = [p for p in active if p.severity == severity_filter]
    return active


def _build_report(
    backend: GuardrailBackend,
    run_id: str,
    timestamp: str,
    probe_results: List[ProbeResult],
    skipped_backends: Optional[Dict[str, str]] = None,
) -> RedTeamReport:
    n_skipped = sum(1 for pr in probe_results if pr.skipped)
    active = [pr for pr in probe_results if not pr.skipped]
    total = len(active)
    n_passed = sum(1 for pr in active if pr.passed)
    n_failed = total - n_passed
    pass_rate = n_passed / total if total else 0.0
    avg_latency = sum(pr.latency_ms for pr in active) / total if total else 0.0
    total_possible = len(probe_results)  # includes skipped
    coverage_pct = round(total / total_possible * 100, 1) if total_possible else 0.0

    by_category: Dict[str, Dict[str, Any]] = {}
    for pr in active:
        ref = pr.probe.owasp_ref
        b = by_category.setdefault(ref, {"total": 0, "passed": 0, "failed": 0})
        b["total"] += 1
        if pr.passed:
            b["passed"] += 1
        else:
            b["failed"] += 1
    for stats in by_category.values():
        stats["pass_rate"] = round(
            stats["passed"] / stats["total"] if stats["total"] else 0.0, 4
        )

    by_severity: Dict[str, Dict[str, Any]] = {}
    for pr in active:
        sev = pr.probe.severity
        b = by_severity.setdefault(sev, {"total": 0, "passed": 0, "failed": 0})
        b["total"] += 1
        if pr.passed:
            b["passed"] += 1
        else:
            b["failed"] += 1
    for stats in by_severity.values():
        stats["pass_rate"] = round(
            stats["passed"] / stats["total"] if stats["total"] else 0.0, 4
        )

    return RedTeamReport(
        backend=backend,
        run_id=run_id,
        timestamp=timestamp,
        total_probes=total,
        passed=n_passed,
        failed=n_failed,
        pass_rate=round(pass_rate, 4),
        results_by_category=by_category,
        results_by_severity=by_severity,
        average_latency_ms=round(avg_latency, 2),
        probe_results=probe_results,
        skipped_count=n_skipped,
        skipped_backends=skipped_backends or {},
        coverage_pct=coverage_pct,
    )


def _build_timeout_report(
    backend: GuardrailBackend,
    probes: List[AttackProbe],
    timestamp: str,
    reason: str = "TIMEOUT",
) -> RedTeamReport:
    now = datetime.now(timezone.utc).isoformat()
    probe_results = [
        ProbeResult(
            probe=probe,
            backend=backend,
            actual_action=None,
            expected_action=probe.expected_action,
            passed=None,
            latency_ms=0.0,
            timestamp=now,
            raw_response=GuardrailResult(
                backend_used=backend,
                action=ActionType.SKIPPED,
                findings={"skipped": True, "reason": reason},
            ),
            skipped=True,
            skip_reason=reason,
        )
        for probe in probes
    ]
    return _build_report(
        backend, str(uuid4()), timestamp, probe_results,
        skipped_backends={backend.value: reason},
    )


def _compute_category_winners(
    reports: Dict[str, RedTeamReport],
) -> Dict[str, str]:
    """For each OWASP ref, return the backend.value with the highest pass_rate."""
    all_refs: Set[str] = set()
    for r in reports.values():
        all_refs.update(r.results_by_category)

    winners: Dict[str, str] = {}
    for ref in all_refs:
        candidates = [
            (b, r.results_by_category[ref]["pass_rate"])
            for b, r in reports.items()
            if ref in r.results_by_category
        ]
        if candidates:
            winners[ref] = max(candidates, key=lambda t: t[1])[0]
    return winners


def _build_summary_table(
    reports: Dict[str, RedTeamReport],
) -> List[Dict[str, Any]]:
    """Flat rows — one per (backend × category) — for dashboard rendering."""
    rows: List[Dict[str, Any]] = []
    for backend_val, report in reports.items():
        for ref, stats in report.results_by_category.items():
            rows.append(
                {
                    "backend": backend_val,
                    "owasp_ref": ref,
                    "total": stats["total"],
                    "passed": stats["passed"],
                    "failed": stats["failed"],
                    "pass_rate": stats["pass_rate"],
                    "average_latency_ms": report.average_latency_ms,
                }
            )
    rows.sort(key=lambda r: (r["owasp_ref"], r["backend"]))
    return rows


def _diff_row(
    baseline: ProbeResult,
    current: ProbeResult,
    flag: str,
) -> Dict[str, Any]:
    """Build a regression/improvement row for run_regression output."""
    return {
        "flag": flag,                                      # "RED" or "GREEN"
        "probe_id": baseline.probe.id,
        "owasp_ref": baseline.probe.owasp_ref,
        "category": baseline.probe.category.value,
        "severity": baseline.probe.severity,
        "description": baseline.probe.description,
        "tags": baseline.probe.tags,
        "baseline_action": baseline.actual_action.value if baseline.actual_action else "skipped",
        "current_action": current.actual_action.value if current.actual_action else "skipped",
        "expected_action": baseline.probe.expected_action.value,
        "baseline_latency_ms": baseline.latency_ms,
        "current_latency_ms": current.latency_ms,
        "latency_delta_ms": round(current.latency_ms - baseline.latency_ms, 2),
    }
