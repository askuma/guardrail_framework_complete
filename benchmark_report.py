#!/usr/bin/env python3
"""benchmark_report.py — Monthly OWASP LLM Top 10 guardrail benchmark.

Detects reachable backends, runs the full probe library against them,
and generates JSON, Markdown, and a signed PDF artifact.

Usage
-----
    python3 benchmark_report.py [--year YYYY] [--month MM] [--dry-run]
                                [--backends b1,b2,...] [--output-dir DIR]

    python3 benchmark_report.py --dry-run
    python3 benchmark_report.py --year 2026 --month 6
"""

from __future__ import annotations

import argparse
import calendar
import json
import logging
import os
import sys

from dotenv import load_dotenv
load_dotenv()
import traceback
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as _FuturesTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
# ── Framework imports ──────────────────────────────────────────────────────────

from guardrail_framework.core import (
    GuardrailBackend,
    GuardrailFramework,
    get_framework,
)
from guardrail_framework.probes import ProbeLibrary
from guardrail_framework.red_team_runner import ComparisonReport, RedTeamRunner

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ── Constants ──────────────────────────────────────────────────────────────────

PROBE_LIBRARY_VERSION = "0.1.0"
_BACKEND_CHECK_TIMEOUT = 5  # seconds per backend

REASON_UNAVAILABLE     = "UNAVAILABLE"
REASON_PENDING_LLM     = "PENDING_LLM_CREDITS"
REASON_TIMEOUT         = "TIMEOUT"

_TESTABLE_BACKENDS = [
    GuardrailBackend.NEMO,
    GuardrailBackend.GUARDRAILS_AI,
    GuardrailBackend.PRESIDIO,
    GuardrailBackend.LAKERA,
    GuardrailBackend.GA_GUARD,
]


# ── Dataclasses ────────────────────────────────────────────────────────────────


@dataclass
class BenchmarkArtifacts:
    """Paths and metadata for one completed benchmark run."""

    year: int
    month: int
    run_id: str
    pdf_path: Optional[str]
    json_path: str
    markdown_path: str
    comparison_report: Optional[ComparisonReport]
    delta: Optional[Dict[str, Any]]
    backends_tested: List[str] = field(default_factory=list)
    backends_skipped: Dict[str, str] = field(default_factory=dict)
    probe_count: int = 0
    generated_at: Optional[datetime] = None


# ── Serialisation helpers ──────────────────────────────────────────────────────


def _enum_safe(v: Any) -> Any:
    """Recursively replace Enum instances with their .value for JSON output."""
    if isinstance(v, dict):
        return {k: _enum_safe(val) for k, val in v.items()}
    if isinstance(v, list):
        return [_enum_safe(i) for i in v]
    if hasattr(v, "value"):
        return v.value
    return v


def _serialise_comparison(report: ComparisonReport) -> Dict[str, Any]:
    """Convert ComparisonReport to a JSON-safe dict (no raw payloads)."""
    backend_summaries: Dict[str, Any] = {}
    for bname, r in report.reports.items():
        backend_summaries[bname] = {
            "pass_rate": r.pass_rate,
            "passed": r.passed,
            "failed": r.failed,
            "total_probes": r.total_probes,
            "average_latency_ms": round(r.average_latency_ms, 2),
            "results_by_category": r.results_by_category,
            "results_by_severity": r.results_by_severity,
        }
    return {
        "run_id": report.run_id,
        "timestamp": report.timestamp,
        "backends_tested": [b.value for b in report.backends_tested],
        "best_overall": report.best_overall,
        "worst_overall": report.worst_overall,
        "category_winners": report.category_winners,
        "summary_table": _enum_safe(report.summary_table),
        "backend_summaries": backend_summaries,
    }


# ── BenchmarkRunner ────────────────────────────────────────────────────────────


class BenchmarkRunner:
    """Orchestrates monthly benchmark generation.

    Detects which backends are reachable, runs the full probe suite,
    computes a month-over-month delta if prior data exists, and writes
    JSON, Markdown, and (best-effort) signed PDF artifacts.
    """

    def __init__(self, framework: Optional[GuardrailFramework] = None) -> None:
        self._framework = framework or get_framework()
        self._runner    = RedTeamRunner(framework=self._framework)
        self._library   = ProbeLibrary()

        # /app/benchmarks/ inside the container, ./benchmarks/ locally
        self._default_output = (
            Path("/app/benchmarks")
            if Path("/app").is_dir()
            else Path("./benchmarks")
        )
        self._docs_index = Path("docs/latest_index.json")

    # ── Public API ─────────────────────────────────────────────────────────────

    def generate_monthly_benchmark(
        self,
        year: int,
        month: int,
        backends: Optional[List[GuardrailBackend]] = None,
        dry_run: bool = False,
        output_dir: Optional[Path] = None,
    ) -> BenchmarkArtifacts:
        """Run all probes against all backends, write artifacts.

        Parameters
        ----------
        year, month:
            Target reporting period.
        backends:
            Explicit list of backends to attempt.  Defaults to all nine
            registered backends.
        dry_run:
            When True, no error is raised if all backends are skipped.
        output_dir:
            Directory for artifact files.  Defaults to /app/benchmarks/
            (container) or ./benchmarks/ (local).
        """
        out_dir = Path(output_dir) if output_dir else self._default_output
        out_dir.mkdir(parents=True, exist_ok=True)

        all_backends = backends or [b for b in GuardrailBackend if b is not GuardrailBackend.CUSTOM]
        now = datetime.now(timezone.utc)
        logger.info("Benchmark run (%04d-%02d)  backends=%s  dry_run=%s",
                    year, month, [b.value for b in all_backends], dry_run)

        comparison = self._runner.compare_backends(backends=all_backends, categories=None)

        backends_tested = [
            b.value for b in comparison.backends_tested
            if b.value not in comparison.skipped_backends
        ]
        backends_skipped = dict(comparison.skipped_backends)
        probe_count = sum(r.total_probes for r in comparison.reports.values())

        if not backends_tested and not dry_run:
            raise RuntimeError(
                "No backends returned results — all were skipped. "
                f"Skipped: {list(backends_skipped.keys())}. "
                "Set dry_run=True to proceed anyway."
            )

        stem = f"benchmark_{year:04d}_{month:02d}"
        artifacts = BenchmarkArtifacts(
            year=year,
            month=month,
            run_id=comparison.run_id,
            pdf_path=None,
            json_path=str(out_dir / f"{stem}.json"),
            markdown_path=str(out_dir / f"{stem}.md"),
            comparison_report=comparison,
            delta=None,
            backends_tested=backends_tested,
            backends_skipped=backends_skipped,
            probe_count=probe_count,
            generated_at=now,
        )

        prior_path = out_dir / _prior_month_filename(year, month)
        if prior_path.exists():
            try:
                artifacts.delta = self._compute_delta(comparison, year, month, out_dir)
            except Exception as exc:
                logger.warning("Month-over-month delta failed: %s", exc)

        self._generate_artifacts(artifacts, comparison, artifacts.delta, [])
        self._update_docs_index(artifacts)

        logger.info(
            "Done — JSON: %s  MD: %s  PDF: %s",
            artifacts.json_path,
            artifacts.markdown_path,
            artifacts.pdf_path or "(skipped)",
        )
        return artifacts

    def get_latest_benchmark(self, output_dir: Optional[Path] = None) -> Optional[Dict]:
        """Return the most-recent benchmark JSON as a dict, or None."""
        out_dir = Path(output_dir) if output_dir else self._default_output
        candidates = sorted(out_dir.glob("benchmark_*.json"))
        if not candidates:
            return None
        with open(candidates[-1]) as fh:
            return json.load(fh)

    def list_all_benchmarks(self, output_dir: Optional[Path] = None) -> List[Dict]:
        """Return metadata dicts for every benchmark JSON on disk."""
        out_dir = Path(output_dir) if output_dir else self._default_output
        result = []
        for path in sorted(out_dir.glob("benchmark_*.json")):
            try:
                with open(path) as fh:
                    data = json.load(fh)
                result.append(data.get("metadata", {}))
            except Exception:
                pass
        return result

    # ── Backend detection ──────────────────────────────────────────────────────

    def _detect_reachable_backends(
        self,
        backends: List[GuardrailBackend],
    ) -> Tuple[List[GuardrailBackend], List[Tuple[str, str]]]:
        """Fire one lightweight probe at each backend within a 5-second timeout.

        Returns
        -------
        (reachable, [(backend_value, skip_reason), ...])
        """
        # LLM09 probes are short text questions — least likely to timeout
        probe_pool = self._library.get_by_owasp_ref("LLM09") or self._library.all_probes()
        health_probe = probe_pool[0]

        reachable: List[GuardrailBackend] = []
        skipped: List[Tuple[str, str]] = []

        for backend in backends:
            reason = self._check_one_backend(backend, health_probe)
            if reason is None:
                reachable.append(backend)
            else:
                skipped.append((backend.value, reason))
                logger.info("Backend %-15s  SKIPPED  (%s)", backend.value, reason)

        return reachable, skipped

    def _check_one_backend(self, backend: GuardrailBackend, probe: Any) -> Optional[str]:
        """Return None if backend is reachable, or a REASON_* string if not.

        Fast-paths for remote backends that need API keys are applied before
        attempting the probe to avoid noisy network errors in logs.
        """
        if backend == GuardrailBackend.LAKERA and not os.getenv("LAKERA_GUARD_API_KEY"):
            return REASON_UNAVAILABLE
        if backend == GuardrailBackend.GA_GUARD and not (
            os.getenv("GA_GUARD_API_KEY") and os.getenv("GA_GUARD_API_URL")
        ):
            return REASON_UNAVAILABLE

        def _run() -> None:
            self._runner.run_against_backend(backend, probes=[probe])

        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_run)
                future.result(timeout=_BACKEND_CHECK_TIMEOUT)
            return None
        except _FuturesTimeout:
            return REASON_TIMEOUT
        except Exception as exc:
            msg = str(exc).lower()
            if any(k in msg for k in ("auth", "401", "403", "api_key", "credit", "quota", "unauthorized")):
                return REASON_PENDING_LLM
            return REASON_UNAVAILABLE

    # ── Month-over-month delta ─────────────────────────────────────────────────

    def _compute_delta(
        self,
        current: ComparisonReport,
        year: int,
        month: int,
        out_dir: Path,
    ) -> Optional[Dict[str, Any]]:
        """Compute structured month-over-month delta in spec format."""
        prior_path = out_dir / _prior_month_filename(year, month)
        if not prior_path.exists():
            return None

        try:
            prior_data: Dict[str, Any] = json.loads(prior_path.read_text())
        except Exception:
            return None

        prior_summaries: Dict[str, Any] = (
            prior_data.get("results", {}).get("backend_summaries", {})
        )
        prior_meta: Dict[str, Any] = prior_data.get("metadata", {})
        prior_backends: set = set(prior_meta.get("backends_tested", []))
        prior_probe_count: int = prior_meta.get("probe_count", 0)

        active_backends = {
            b.value for b in current.backends_tested
            if b.value not in current.skipped_backends
        }

        per_backend: Dict[str, Dict[str, Any]] = {}
        improvements: List[Dict[str, Any]] = []
        regressions: List[Dict[str, Any]] = []

        for bname in sorted(active_backends):
            r = current.reports.get(bname)
            if not r:
                continue
            current_pct = round(r.pass_rate * 100, 2)
            prior_rec = prior_summaries.get(bname, {})
            prior_pct_raw = prior_rec.get("pass_rate")

            if prior_pct_raw is not None:
                prior_pct_f: float = round(float(prior_pct_raw) * 100, 2)
                prior_pct: Optional[float] = prior_pct_f
                delta_pct = round(current_pct - prior_pct_f, 2)
                if delta_pct >= 5:
                    status = "improvement"
                    improvements.append({"backend": bname, "delta": delta_pct})
                elif delta_pct <= -5:
                    status = "regression"
                    regressions.append({"backend": bname, "delta": delta_pct})
                else:
                    status = "stable"
            else:
                prior_pct = None
                delta_pct = 0.0
                status = "new"

            per_backend[bname] = {
                "delta": delta_pct,
                "current": current_pct,
                "prior": prior_pct,
                "status": status,
            }

        improvements.sort(key=lambda x: x["delta"], reverse=True)
        regressions.sort(key=lambda x: x["delta"])

        current_probe_count = (
            sum(r.total_probes for r in current.reports.values())
            // max(len(current.reports), 1)
        )

        if month == 1:
            prior_year, prior_month_num = year - 1, 12
        else:
            prior_year, prior_month_num = year, month - 1

        return {
            "prior_month": f"{prior_year}-{prior_month_num:02d}",
            "per_backend": per_backend,
            "best_improvement": improvements[0] if improvements else None,
            "worst_regression": regressions[0] if regressions else None,
            "new_probes_added": max(0, current_probe_count - prior_probe_count),
            "backends_added": sorted(active_backends - prior_backends),
            "backends_removed": sorted(prior_backends - active_backends),
        }

    def _compute_month_over_month_delta(
        self,
        current: ComparisonReport,
        prior_json_path: str,
    ) -> Dict[str, Any]:
        """Compute pass-rate changes between current and prior-month reports.

        Flags regressions (>5% drop) and improvements (>5% gain).
        """
        with open(prior_json_path) as fh:
            prior_data = json.load(fh)

        prior_summaries: Dict[str, Any] = (
            prior_data.get("results", {}).get("backend_summaries", {})
        )
        prior_probe_count: int = prior_data.get("metadata", {}).get("probe_count", 0)
        current_probe_count: int = (
            sum(r.total_probes for r in current.reports.values())
            // max(len(current.reports), 1)
        )

        backend_delta: Dict[str, Any] = {}
        regressions: List[Dict] = []
        improvements: List[Dict] = []

        for bname, report in current.reports.items():
            cur_rate  = report.pass_rate
            prior_rec = prior_summaries.get(bname, {})
            prev_rate = prior_rec.get("pass_rate")

            if prev_rate is None:
                backend_delta[bname] = {"current": cur_rate, "prior": None, "change": None}
                continue

            change = round(cur_rate - prev_rate, 4)
            backend_delta[bname] = {"current": cur_rate, "prior": prev_rate, "change": change}

            if change <= -0.05:
                regressions.append({"backend": bname, "change": change})
            elif change >= 0.05:
                improvements.append({"backend": bname, "change": change})

        # Per-category average delta across all shared backends
        prior_cat: Dict[str, List[float]] = defaultdict(list)
        for bdata in prior_summaries.values():
            for cat, stats in bdata.get("results_by_category", {}).items():
                prior_cat[cat].append(stats.get("pass_rate", 0.0))

        current_cat: Dict[str, List[float]] = defaultdict(list)
        for report in current.reports.values():
            for cat, stats in report.results_by_category.items():
                current_cat[cat].append(stats.get("pass_rate", 0.0))

        category_delta: Dict[str, Optional[float]] = {}
        for cat in set(list(prior_cat.keys()) + list(current_cat.keys())):
            pa = (sum(prior_cat[cat]) / len(prior_cat[cat])) if prior_cat[cat] else None
            ca = (sum(current_cat[cat]) / len(current_cat[cat])) if current_cat[cat] else None
            category_delta[cat] = round(ca - pa, 4) if (pa is not None and ca is not None) else None

        return {
            "backend_delta": backend_delta,
            "category_delta": category_delta,
            "regressions":  sorted(regressions,  key=lambda x: x["change"]),
            "improvements": sorted(improvements, key=lambda x: x["change"], reverse=True),
            "new_probes_total": max(current_probe_count - prior_probe_count, 0),
        }

    # ── Artifact generation ────────────────────────────────────────────────────

    def _generate_artifacts(
        self,
        artifacts: BenchmarkArtifacts,
        comparison: ComparisonReport,
        delta: Optional[Dict],
        pending_detail: List[Dict],
    ) -> None:
        year, month = artifacts.year, artifacts.month

        # Probe count per backend (all backends run the same set)
        probe_count = (
            sum(r.total_probes for r in comparison.reports.values())
            // max(len(comparison.reports), 1)
        )

        # ── JSON ──────────────────────────────────────────────────────────────
        _first_report = next((r for r in comparison.reports.values() if r.total_probes > 0), None)
        owasp_probe_count = 0
        cm_probe_count = 0
        if _first_report:
            for _pr in _first_report.probe_results:
                if _pr.probe.id.startswith("CM-"):
                    cm_probe_count += 1
                else:
                    owasp_probe_count += 1

        json_payload: Dict[str, Any] = {
            "metadata": {
                "report_title": f"GuardrailProbe Benchmark — {calendar.month_name[month]} {year}",
                "generated_at": (artifacts.generated_at or datetime.now(timezone.utc)).isoformat(),
                "run_id": comparison.run_id,
                "probe_library_version": PROBE_LIBRARY_VERSION,
                "guardrailprobe_version": PROBE_LIBRARY_VERSION,
                "probe_count": probe_count,
                "owasp_probe_count": owasp_probe_count,
                "content_moderation_probe_count": cm_probe_count,
                "backends_tested": artifacts.backends_tested,
                "backends_skipped": artifacts.backends_skipped,
            },
            "results": _serialise_comparison(comparison),
            "delta": delta,
        }

        with open(artifacts.json_path, "w") as fh:
            json.dump(json_payload, fh, indent=2)
        logger.info("JSON  → %s", artifacts.json_path)

        # ── Markdown ──────────────────────────────────────────────────────────
        md = _render_markdown(artifacts, comparison, delta, pending_detail)
        with open(artifacts.markdown_path, "w") as fh:
            fh.write(md)
        logger.info("MD    → %s", artifacts.markdown_path)

        # ── PDF (best-effort — never blocks the run) ──────────────────────────
        try:
            from guardrail_framework.report_signer import ReportSigner  # noqa: PLC0415
            signer  = ReportSigner()
            pdf_out = artifacts.json_path.replace(".json", ".pdf")
            signer.generate_signed_report(comparison, pdf_out)
            artifacts.pdf_path = pdf_out
            logger.info("PDF   → %s", pdf_out)
        except Exception as exc:
            logger.warning("PDF signing skipped (%s)", exc)

    def _write_empty_artifacts(
        self,
        artifacts: BenchmarkArtifacts,
        pending_detail: List[Dict],
        year: int,
        month: int,
    ) -> None:
        """Write placeholder JSON/MD when no backends were reachable (dry_run)."""
        payload = {
            "metadata": {
                "report_title": f"GuardrailProbe Benchmark — {calendar.month_name[month]} {year}",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "run_id": artifacts.run_id,
                "probe_library_version": PROBE_LIBRARY_VERSION,
                "probe_count": 0,
                "backends_tested": [],
                "backends_skipped": artifacts.backends_skipped,
            },
            "results": {},
            "delta": None,
        }
        with open(artifacts.json_path, "w") as fh:
            json.dump(payload, fh, indent=2)

        with open(artifacts.markdown_path, "w") as fh:
            fh.write(
                f"# GuardrailProbe Benchmark — {calendar.month_name[month]} {year}\n\n"
                "> No backends were reachable during this run.\n\n"
                "## Backends Pending\n\n"
                + "\n".join(
                    f"- **{p['backend']}**: {p['reason']} — {p['note']}"
                    for p in pending_detail
                )
                + "\n"
            )

    # ── docs/latest_index.json ─────────────────────────────────────────────────

    def _update_docs_index(self, artifacts: BenchmarkArtifacts) -> None:
        """Append this run to docs/latest_index.json for the GitHub Pages site."""
        if not self._docs_index.parent.exists():
            return  # docs/ not present — running outside repo root

        index: Dict[str, Any]
        try:
            with open(self._docs_index) as fh:
                index = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            index = {"latest": None, "archive": []}

        cr = artifacts.comparison_report
        meta = {
            "year":          artifacts.year,
            "month":         artifacts.month,
            "month_name":    calendar.month_name[artifacts.month],
            "run_id":        artifacts.run_id,
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "backends_tested": artifacts.backends_tested,
            "best_overall":  cr.best_overall if cr else None,
            "best_score": (
                round(cr.reports[cr.best_overall].pass_rate * 100, 1)
                if (cr and cr.best_overall and cr.best_overall in cr.reports) else None
            ),
            "probe_count":   artifacts.probe_count,
            "backends_skipped": artifacts.backends_skipped,
            "json_url":     (
                f"benchmarks/benchmark_{artifacts.year:04d}_{artifacts.month:02d}.json"
            ),
            "markdown_url": (
                f"benchmarks/benchmark_{artifacts.year:04d}_{artifacts.month:02d}.md"
            ),
            "pdf_url": (
                f"benchmarks/benchmark_{artifacts.year:04d}_{artifacts.month:02d}.pdf"
                if artifacts.pdf_path else None
            ),
        }

        index["latest"] = meta  # type: ignore[assignment]
        # Replace any existing entry for the same month
        index["archive"] = [  # type: ignore[assignment]
            e for e in index.get("archive", [])
            if not (e.get("year") == artifacts.year and e.get("month") == artifacts.month)
        ]
        index["archive"].append(meta)
        index["archive"].sort(key=lambda e: (e["year"], e["month"]))

        with open(self._docs_index, "w") as fh:
            json.dump(index, fh, indent=2)
        logger.info("Index → %s", self._docs_index)


# ── Markdown renderer ──────────────────────────────────────────────────────────


def _render_markdown(
    artifacts: BenchmarkArtifacts,
    comparison: ComparisonReport,
    delta: Optional[Dict],
    pending_detail: List[Dict],
) -> str:
    year, month = artifacts.year, artifacts.month
    month_name  = calendar.month_name[month]

    template_path = Path(__file__).parent / "benchmark_template.md"
    template = template_path.read_text(encoding="utf-8")

    best      = comparison.best_overall
    best_rate = comparison.reports[best].pass_rate

    improvement_backend = "none this month"
    improvement_delta   = "0.0"
    regression_backend  = "none this month"
    regression_delta    = "0.0"
    if delta:
        bi = delta.get("best_improvement")
        wr = delta.get("worst_regression")
        if bi:
            improvement_backend = bi["backend"]
            improvement_delta   = f"{bi['delta']:.1f}"
        if wr:
            regression_backend = wr["backend"]
            regression_delta   = f"{abs(wr['delta']):.1f}"

    subs: Dict[str, str] = {
        "{MONTH}":                   month_name,
        "{YEAR}":                    str(year),
        "{BEST_OVERALL_BACKEND}":    best,
        "{BEST_OVERALL_SCORE}":      f"{best_rate * 100:.1f}",
        "{RATIO_WINNER}":            _tm_ratio_winner(comparison),
        "{IMPROVEMENT_BACKEND}":     improvement_backend,
        "{IMPROVEMENT_DELTA}":       improvement_delta,
        "{REGRESSION_BACKEND}":      regression_backend,
        "{REGRESSION_DELTA}":        regression_delta,
        "{BACKENDS_TESTED_COUNT}":   str(len(comparison.backends_tested)),
        "{BACKENDS_SKIPPED_COUNT}":  str(len(comparison.skipped_backends)),
        "{TOTAL_PROBES}":            str(sum(r.total_probes for r in comparison.reports.values())),
        "{GENERATED_AT}":            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "{RUN_ID}":                  comparison.run_id,
        "{OVERALL_TABLE_ROWS}":      _tm_overall_rows(comparison, delta),
        "{CONTENT_MODERATION_TABLE_ROWS}": _tm_cm_rows(comparison),
        "{LATENCY_TABLE_ROWS}":      _tm_latency_rows(comparison),
        "{NOTABLE_BYPASSES_LIST}":   _tm_bypasses(comparison),
        "{SKIPPED_BACKENDS_TABLE}":  _tm_skipped_table(comparison, pending_detail),
        "{DELTA_SECTION}":           _tm_delta_section(delta),
        "{VERSION}":                 PROBE_LIBRARY_VERSION,
    }

    for ref, data in _tm_per_category(comparison).items():
        subs[f"{{{ref}_WINNER}}"]       = data["winner"]
        subs[f"{{{ref}_SCORE}}"]        = data["score"]
        subs[f"{{{ref}_SECOND}}"]       = data["second"]
        subs[f"{{{ref}_SECOND_SCORE}}"] = data["second_score"]

    result = template
    for key, value in subs.items():
        result = result.replace(key, value)
    return result


# ── Template section builders ──────────────────────────────────────────────────


def _tm_ratio_winner(comparison: ComparisonReport) -> str:
    """Backend with the best pass_rate * 1000 / avg_latency_ms ratio."""
    best_ratio, winner = -1.0, "—"
    for bname, r in comparison.reports.items():
        if bname in comparison.skipped_backends or r.average_latency_ms <= 0:
            continue
        ratio = r.pass_rate * 1000 / max(r.average_latency_ms, 1)
        if ratio > best_ratio:
            best_ratio, winner = ratio, bname
    return winner


def _tm_overall_rows(comparison: ComparisonReport, delta: Optional[Dict]) -> str:
    rows: List[str] = []
    for backend in comparison.backends_tested:
        bname = backend.value
        if bname in comparison.skipped_backends:
            reason = comparison.skipped_backends[bname]
            rows.append(f"| {bname} | SKIPPED ({reason}) | — | — | — | — |")
            continue
        r = comparison.reports.get(bname)
        if not r:
            continue
        vs_last = "—"
        if delta:
            per_b = (delta.get("per_backend") or {}).get(bname, {})
            d = per_b.get("delta")
            if d is not None:
                sign = "+" if d >= 0 else ""
                flag = " 🔴" if d <= -5 else (" 🟢" if d >= 5 else "")
                vs_last = f"{sign}{d:.1f}%{flag}"
        cats = r.results_by_category
        best_cat  = max(cats, key=lambda c: cats[c].get("pass_rate", 0)) if cats else "—"
        worst_cat = min(cats, key=lambda c: cats[c].get("pass_rate", 1)) if cats else "—"
        rows.append(
            f"| {bname} | {r.pass_rate * 100:.1f}% | {vs_last} "
            f"| {best_cat} | {worst_cat} | {r.average_latency_ms:.0f} ms |"
        )
    return "\n".join(rows) or "| (no active backends) | — | — | — | — | — |"


def _tm_cm_rows(comparison: ComparisonReport) -> str:
    """Pass rates for CM-001–CM-020 probes split into Hate/Violence/Sexual/Self-Harm."""
    CM_RANGES = {"Hate": (1, 5), "Violence": (6, 10), "Sexual": (11, 15), "Self-Harm": (16, 20)}

    def _probe_num(pid: str) -> Optional[int]:
        if pid.startswith("CM-"):
            try:
                return int(pid[3:])
            except ValueError:
                pass
        return None

    rows: List[str] = []
    for backend in comparison.backends_tested:
        bname = backend.value
        if bname in comparison.skipped_backends:
            rows.append(f"| {bname} | — | — | — | — | SKIPPED |")
            continue
        r = comparison.reports.get(bname)
        if not r:
            continue
        cm = [pr for pr in r.probe_results if _probe_num(pr.probe.id) is not None]
        cats: Dict[str, str] = {}
        for cat_name, (lo, hi) in CM_RANGES.items():
            bucket = [pr for pr in cm if lo <= (_probe_num(pr.probe.id) or 0) <= hi]
            if bucket:
                n_pass = sum(1 for pr in bucket if pr.passed is True)
                cats[cat_name] = f"{n_pass / len(bucket) * 100:.0f}%"
            else:
                cats[cat_name] = "—"
        if cm:
            overall = sum(1 for pr in cm if pr.passed is True) / len(cm)
            overall_str = f"{overall * 100:.0f}%"
        else:
            overall_str = "—"
        rows.append(
            f"| {bname} | {cats['Hate']} | {cats['Violence']} "
            f"| {cats['Sexual']} | {cats['Self-Harm']} | {overall_str} |"
        )
    return "\n".join(rows) or "| (no data) | — | — | — | — | — |"


def _tm_latency_rows(comparison: ComparisonReport) -> str:
    active = [
        (bname, r)
        for bname, r in comparison.reports.items()
        if bname not in comparison.skipped_backends and r.total_probes > 0
    ]
    active.sort(key=lambda x: x[1].average_latency_ms)
    rows: List[str] = []
    for bname, r in active:
        ms = r.average_latency_ms
        if ms < 10:
            cat, rec = "Ultra-fast", "Real-time inference, high-throughput pipelines"
        elif ms < 200:
            cat, rec = "Fast", "Standard API protection"
        elif ms < 1000:
            cat, rec = "Moderate", "Batch processing, async pipelines"
        else:
            cat, rec = "Slow", "Offline analysis, compliance audits"
        rows.append(f"| {bname} | {r.pass_rate * 100:.1f}% | {ms:.0f} ms | {cat} | {rec} |")
    return "\n".join(rows) or "| (no active backends) | — | — | — | — |"


def _tm_bypasses(comparison: ComparisonReport) -> str:
    bypasses = _find_universal_bypasses(comparison)
    if not bypasses:
        return "No universal bypasses detected in this run."
    lines = [
        "| OWASP Category | Severity | Count |",
        "|:---------------|:--------:|:-----:|",
    ]
    for entry in bypasses:
        lines.append(f"| {entry['owasp_ref']} | {entry['severity']} | {entry['count']} |")
    return "\n".join(lines)


def _tm_skipped_table(
    comparison: ComparisonReport,
    pending_detail: List[Dict],
) -> str:
    rows: List[str] = []
    for bname, reason in comparison.skipped_backends.items():
        rows.append(f"| {bname} | {reason} | Configure credentials |")
    for p in pending_detail:
        if p["backend"] not in comparison.skipped_backends:
            note = p.get("note", "TBD")
            rows.append(f"| {p['backend']} | {p['reason']} | {note} |")
    return "\n".join(rows) or "| — | — | — |"


def _tm_delta_section(delta: Optional[Dict]) -> str:
    if delta is None:
        return "First benchmark — no prior month comparison available."
    lines: List[str] = []
    new_probes = delta.get("new_probes_added", 0)
    if new_probes:
        lines.append(f"**{new_probes} new probes** added since last month.\n")
    bi = delta.get("best_improvement")
    wr = delta.get("worst_regression")
    if bi:
        lines.append(f"**Best improvement:** {bi['backend']} +{bi['delta']:.1f}%\n")
    if wr:
        lines.append(f"**Worst regression:** {wr['backend']} {wr['delta']:.1f}%\n")
    per_b = delta.get("per_backend") or {}
    if per_b:
        lines += [
            "**All backend changes:**\n",
            "| Backend | Previous | Current | Change | Status |",
            "|---------|----------|---------|--------|--------|",
        ]
        for bname, data in per_b.items():
            prev   = f"{data['prior']:.1f}%" if data.get("prior") is not None else "—"
            curr   = f"{data['current']:.1f}%"
            chg    = f"{data['delta']:+.1f}%" if data.get("delta") is not None else "—"
            status = data.get("status", "—")
            lines.append(f"| {bname} | {prev} | {curr} | {chg} | {status} |")
    new_b = delta.get("backends_added") or []
    rem_b = delta.get("backends_removed") or []
    if new_b:
        lines.append(f"\n**New backends:** {', '.join(new_b)}")
    if rem_b:
        lines.append(f"**Removed backends:** {', '.join(rem_b)}")
    return "\n".join(lines) or "No significant changes from prior month."


def _tm_per_category(comparison: ComparisonReport) -> Dict[str, Dict[str, str]]:
    OWASP_REFS = [
        "LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
        "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
    ]
    result: Dict[str, Dict[str, str]] = {}
    active = {
        bname: r
        for bname, r in comparison.reports.items()
        if bname not in comparison.skipped_backends
    }
    for ref in OWASP_REFS:
        scores = sorted(
            ((bname, r.results_by_category.get(ref, {}).get("pass_rate", 0.0))
             for bname, r in active.items()),
            key=lambda x: x[1],
            reverse=True,
        )
        result[ref] = {
            "winner":       scores[0][0]                  if scores           else "—",
            "score":        f"{scores[0][1] * 100:.0f}"   if scores           else "—",
            "second":       scores[1][0]                  if len(scores) > 1  else "—",
            "second_score": f"{scores[1][1] * 100:.0f}"   if len(scores) > 1  else "—",
        }
    return result


def _find_universal_bypasses(comparison: ComparisonReport) -> List[Dict]:
    """Return probes that explicitly failed on every active backend, grouped by ref + severity."""
    if not comparison.reports:
        return []

    active_backends = [
        bname for bname in comparison.reports
        if bname not in comparison.skipped_backends
    ]
    if not active_backends:
        return []

    failed_on: Dict[str, set] = defaultdict(set)
    probe_meta: Dict[str, Dict] = {}

    for bname in active_backends:
        for pr in comparison.reports[bname].probe_results:
            if pr.passed is False:          # skip None (preflight-skipped probes)
                failed_on[pr.probe.id].add(bname)
                probe_meta[pr.probe.id] = {
                    "owasp_ref": pr.probe.owasp_ref,
                    "severity":  pr.probe.severity,
                }

    n_backends = len(active_backends)
    groups: Dict[tuple, int] = {}
    for pid, backends in failed_on.items():
        if len(backends) == n_backends:
            m = probe_meta[pid]
            key = (m["owasp_ref"], m["severity"])
            groups[key] = groups.get(key, 0) + 1

    return [
        {"owasp_ref": k[0], "severity": k[1], "count": v}
        for k, v in sorted(groups.items())
    ]


# ── Misc helpers ───────────────────────────────────────────────────────────────


def _prior_month_filename(year: int, month: int) -> str:
    if month == 1:
        return f"benchmark_{year - 1:04d}_12.json"
    return f"benchmark_{year:04d}_{month - 1:02d}.json"


def _pending_note(reason: str) -> str:
    if reason == REASON_PENDING_LLM:
        return "Will be included once LLM credits are provisioned"
    if reason == REASON_UNAVAILABLE:
        return "SDK not installed or API credentials not configured"
    if reason == REASON_TIMEOUT:
        return "Backend did not respond within 5 s during health check"
    return "Unknown"


# ── CLI ────────────────────────────────────────────────────────────────────────


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    now = datetime.now(timezone.utc)
    p = argparse.ArgumentParser(
        description="Generate the GuardrailProbe monthly benchmark report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 benchmark_report.py --dry-run\n"
            "  python3 benchmark_report.py --year 2026 --month 6\n"
            "  python3 benchmark_report.py --backends guardrails_ai,presidio\n"
        ),
    )
    p.add_argument("--year",   type=int, default=now.year,  help="Report year (default: current year)")
    p.add_argument("--month",  type=int, default=now.month, help="Report month 1-12 (default: current month)")
    p.add_argument("--dry-run", dest="dry_run", action="store_true", default=False,
                   help="Skip unreachable backends silently; never raise on empty result")
    p.add_argument(
        "--backends", type=str, default="",
        help=(
            "Comma-separated backends to test (default: all). "
            "Valid values: nemo, guardrails_ai, presidio, lakera, ga_guard"
        ),
    )
    p.add_argument(
        "--output-dir", type=str, default="./benchmarks/",
        help="Directory for artifact files (default: ./benchmarks/)",
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = _parse_args(argv)

    if not 1 <= args.month <= 12:
        print(f"Error: --month must be 1-12, got {args.month}", file=sys.stderr)
        sys.exit(1)

    backends: Optional[List[GuardrailBackend]] = None
    if args.backends:
        try:
            backends = [
                GuardrailBackend(name.strip())
                for name in args.backends.split(",")
                if name.strip()
            ]
        except ValueError as exc:
            print(f"Error: invalid backend — {exc}", file=sys.stderr)
            sys.exit(1)

    runner = BenchmarkRunner(framework=get_framework())

    try:
        arts = runner.generate_monthly_benchmark(
            year=args.year,
            month=args.month,
            backends=backends,
            dry_run=args.dry_run,
            output_dir=Path(args.output_dir),
        )
    except Exception as exc:
        print(f"\nBenchmark FAILED: {exc}", file=sys.stderr)
        if os.getenv("DEBUG"):
            traceback.print_exc()
        sys.exit(1)

    print(f"\nBenchmark complete — {calendar.month_name[args.month]} {args.year}")
    print(f"  JSON:     {arts.json_path}")
    print(f"  Markdown: {arts.markdown_path}")
    if arts.pdf_path:
        print(f"  PDF:      {arts.pdf_path}")

    if arts.comparison_report:
        cr = arts.comparison_report
        print(f"\n  Best overall: {cr.best_overall}")
        for b in cr.backends_tested:
            r = cr.reports[b.value]
            print(f"  {b.value:<22}  {r.pass_rate*100:.1f}%  ({r.passed}/{r.total_probes})")


if __name__ == "__main__":
    main()
