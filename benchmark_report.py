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
import traceback
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as _FuturesTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

# ── Framework imports ──────────────────────────────────────────────────────────

from guardrail_framework.core import (
    ActionType,
    GuardrailBackend,
    GuardrailFramework,
    get_framework,
)
from guardrail_framework.probes import AttackCategory, ProbeLibrary
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
    backends_skipped: List[GuardrailBackend] = field(default_factory=list)
    backends_pending: List[str] = field(default_factory=list)


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
        """Detect reachable backends, run all probes, write artifacts.

        Parameters
        ----------
        year, month:
            Target reporting period.
        backends:
            Explicit list of backends to attempt.  Defaults to all five
            standard backends (everything except CUSTOM).
        dry_run:
            When True, unreachable backends are silently skipped and no
            error is raised if none are reachable.
        output_dir:
            Directory for artifact files.  Defaults to /app/benchmarks/
            (container) or ./benchmarks/ (local).
        """
        out_dir = Path(output_dir) if output_dir else self._default_output
        out_dir.mkdir(parents=True, exist_ok=True)

        candidate_backends = backends or _TESTABLE_BACKENDS
        run_id = str(uuid4())
        logger.info("Benchmark run %s  (%04d-%02d)  dry_run=%s", run_id, year, month, dry_run)

        reachable, skipped_reasons = self._detect_reachable_backends(candidate_backends)
        skipped_backends = [b for b in candidate_backends if b not in reachable]
        pending_detail = [
            {
                "backend": bv,
                "reason":  reason,
                "note":    _pending_note(reason),
            }
            for bv, reason in skipped_reasons
        ]

        stem = f"benchmark_{year:04d}_{month:02d}"
        artifacts = BenchmarkArtifacts(
            year=year,
            month=month,
            run_id=run_id,
            pdf_path=None,
            json_path=str(out_dir / f"{stem}.json"),
            markdown_path=str(out_dir / f"{stem}.md"),
            comparison_report=None,
            delta=None,
            backends_skipped=skipped_backends,
            backends_pending=[p["backend"] for p in pending_detail],
        )

        if not reachable:
            if dry_run:
                logger.warning("No reachable backends — writing empty artifact stubs")
                self._write_empty_artifacts(artifacts, pending_detail, year, month)
                return artifacts
            raise RuntimeError(
                "No reachable backends found. "
                f"Skipped: {[b.value for b in skipped_backends]}. "
                "Set dry_run=True to proceed anyway."
            )

        logger.info("Running probes against: %s", [b.value for b in reachable])
        comparison = self._runner.compare_backends(backends=reachable, categories=None)
        artifacts.comparison_report = comparison
        artifacts.run_id = comparison.run_id

        prior_path = out_dir / _prior_month_filename(year, month)
        if prior_path.exists():
            try:
                artifacts.delta = self._compute_month_over_month_delta(
                    comparison, str(prior_path)
                )
            except Exception as exc:
                logger.warning("Month-over-month delta failed: %s", exc)

        self._generate_artifacts(artifacts, comparison, artifacts.delta, pending_detail)
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
        json_payload = {
            "metadata": {
                "report_title": f"GuardrailProbe Benchmark — {calendar.month_name[month]} {year}",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "run_id": comparison.run_id,
                "probe_library_version": PROBE_LIBRARY_VERSION,
                "probe_count": probe_count,
                "backends_tested": [b.value for b in comparison.backends_tested],
                "backends_skipped": [b.value for b in artifacts.backends_skipped],
                "backends_pending": pending_detail,
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
                "backends_skipped": [b.value for b in artifacts.backends_skipped],
                "backends_pending": pending_detail,
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
            "backends_tested": [b.value for b in cr.backends_tested] if cr else [],
            "best_overall":  cr.best_overall if cr else None,
            "best_overall_pass_rate": (
                round(cr.reports[cr.best_overall].pass_rate * 100, 1) if cr else None
            ),
            "json_url":     (
                f"../benchmarks/benchmark_{artifacts.year:04d}_{artifacts.month:02d}.json"
            ),
            "markdown_url": (
                f"../benchmarks/benchmark_{artifacts.year:04d}_{artifacts.month:02d}.md"
            ),
            "pdf_url": (
                f"../benchmarks/benchmark_{artifacts.year:04d}_{artifacts.month:02d}.pdf"
                if artifacts.pdf_path else None
            ),
        }

        index["latest"] = meta
        # Replace any existing entry for the same month
        index["archive"] = [
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

    best  = comparison.best_overall
    worst = comparison.worst_overall
    best_rate = comparison.reports[best].pass_rate
    probe_count = (
        sum(r.total_probes for r in comparison.reports.values())
        // max(len(comparison.reports), 1)
    )

    # TL;DR strings
    biggest_improvement = "none this month"
    biggest_regression  = "none this month"
    if delta:
        imps = delta.get("improvements", [])
        regs = delta.get("regressions",  [])
        if imps:
            b = imps[0]
            biggest_improvement = f"**{b['backend']}** +{b['change']*100:.1f}%"
        if regs:
            b = regs[0]
            biggest_regression  = f"**{b['backend']}** {b['change']*100:.1f}%"

    lines = [
        f"# GuardrailProbe Benchmark — {month_name} {year}",
        "",
        "> Independent OWASP LLM Top 10 evaluation of AI guardrail backends",
        "",
        "## TL;DR",
        "",
        f"- **Winner:** {best} ({best_rate*100:.1f}% overall pass rate)",
    ]

    if delta:
        lines += [
            f"- **Biggest improvement vs last month:** {biggest_improvement}",
            f"- **Biggest regression:** {biggest_regression}",
        ]

    lines += [
        f"- **Backends tested:** {len(comparison.backends_tested)}",
        f"- **Probes run:** {probe_count} per backend",
        "",
        "---",
        "",
        "## Overall Comparison",
        "",
        "| Backend | Overall % | vs Last Month | Best Category | Worst Category | Avg Latency |",
        "|---------|:---------:|:-------------:|:-------------:|:--------------:|:-----------:|",
    ]

    for b in comparison.backends_tested:
        r = comparison.reports[b.value]

        vs_last = "—"
        if delta:
            bd = delta.get("backend_delta", {}).get(b.value, {})
            ch = bd.get("change")
            if ch is not None:
                sign = "+" if ch >= 0 else ""
                flag = " 🔴" if ch <= -0.05 else (" 🟢" if ch >= 0.05 else "")
                vs_last = f"{sign}{ch*100:.1f}%{flag}"

        cats = r.results_by_category
        best_cat  = max(cats, key=lambda c: cats[c].get("pass_rate", 0))  if cats else "—"
        worst_cat = min(cats, key=lambda c: cats[c].get("pass_rate", 1))  if cats else "—"

        lines.append(
            f"| {b.value} | {r.pass_rate*100:.1f}% | {vs_last} "
            f"| {best_cat} | {worst_cat} | {r.average_latency_ms:.0f} ms |"
        )

    lines += [
        "",
        "---",
        "",
        "## Per-Category Winners",
        "",
        "| Category | Winner | Score | Runner-up | Score |",
        "|----------|:------:|:-----:|:---------:|:-----:|",
    ]

    for cat in AttackCategory:
        scores = [
            (b.value, comparison.reports[b.value].results_by_category.get(cat.value, {}).get("pass_rate", 0.0))
            for b in comparison.backends_tested
        ]
        scores.sort(key=lambda x: x[1], reverse=True)
        w_name, w_score = (scores[0][0], f"{scores[0][1]*100:.0f}%") if scores else ("—", "—")
        r_name, r_score = (scores[1][0], f"{scores[1][1]*100:.0f}%") if len(scores) > 1 else ("—", "—")
        lines.append(f"| {cat.value} | {w_name} | {w_score} | {r_name} | {r_score} |")

    # Notable bypasses
    bypasses = _find_universal_bypasses(comparison)
    lines += [
        "",
        "---",
        "",
        "## Notable Bypasses",
        "",
        "Attacks that bypassed **all** tested backends:",
        "",
    ]

    if bypasses:
        lines += [
            "| OWASP Category | Severity | Count |",
            "|:---------------|:--------:|:-----:|",
        ]
        for entry in bypasses:
            lines.append(f"| {entry['owasp_ref']} | {entry['severity']} | {entry['count']} |")
    else:
        lines.append("No universal bypasses detected in this run.")

    # Pending backends
    if pending_detail:
        lines += [
            "",
            "---",
            "",
            "## Backends Pending",
            "",
            "| Backend | Status | Expected |",
            "|---------|:------:|----------|",
        ]
        next_month_name = calendar.month_name[(month % 12) + 1]
        for p in pending_detail:
            lines.append(
                f"| {p['backend']} | {p['reason']} | {next_month_name} {year} |"
            )

    lines += [
        "",
        "---",
        "",
        "## Methodology",
        "",
        "See [METHODOLOGY.md](../METHODOLOGY.md) for probe construction standards, "
        "OWASP LLM Top 10 mapping, pass/fail logic, and regulatory mapping.",
        "",
        "---",
        "",
        "## How to Reproduce",
        "",
        "```bash",
        "pip install guardrailprobe",
        f"python3 benchmark_report.py --year {year} --month {month} --dry-run",
        "```",
        "",
        "---",
        "",
        "## About GuardrailProbe",
        "",
        "Open-source AI guardrail testing framework.  "
        "[github.com/askuma/guardrailprobe](https://github.com/askuma/guardrailprobe)",
        "",
        f"*Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
        f"Run ID: {comparison.run_id} · "
        f"Probe library v{PROBE_LIBRARY_VERSION}*",
        "",
    ]

    return "\n".join(lines)


def _find_universal_bypasses(comparison: ComparisonReport) -> List[Dict]:
    """Return probes that failed on every tested backend, grouped by ref + severity."""
    if not comparison.reports:
        return []

    all_backends = list(comparison.reports.keys())
    failed_on: Dict[str, set] = defaultdict(set)
    probe_meta: Dict[str, Dict] = {}

    for bname, report in comparison.reports.items():
        for pr in report.probe_results:
            if not pr.passed:
                failed_on[pr.probe.id].add(bname)
                probe_meta[pr.probe.id] = {
                    "owasp_ref": pr.probe.owasp_ref,
                    "severity":  pr.probe.severity,
                }

    n_backends = len(all_backends)
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
