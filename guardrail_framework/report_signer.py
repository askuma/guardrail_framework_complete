"""
PDF generation, digital signing, and verification for red-team reports.

Signing flow
------------
1. Build PDF from RedTeamReport / ComparisonReport  (reportlab)
2. Append an empty signature field                  (pyhanko)
3. Sign with the platform private key               (pyhanko SimpleSigner)
4. Embed RFC 3161 trusted timestamp                 (HTTPTimeStamper)
5. Hash the signed PDF and log the event            (DecisionLogShipper)

Verification flow
-----------------
1. Read embedded signatures from the PDF            (pyhanko PdfFileReader)
2. Validate cryptographic integrity                 (pyhanko_certvalidator)
3. Return {valid, signed_at, run_id}

Key management
--------------
GUARDRAIL_SIGNING_KEY_P12   path to PKCS#12 signing key
                             (auto-generated at guardrail_signing.p12 if absent)
GUARDRAIL_SIGNING_KEY_PASS  passphrase for the PKCS#12 file (default: empty)
GUARDRAIL_TSA_URL            RFC 3161 timestamp authority
                             dev default : http://freetsa.org/tsr
                             DigiCert    : http://timestamp.digicert.com
"""

from __future__ import annotations

import hashlib
import importlib.util
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("ReportSigner")

_PYHANKO_AVAILABLE   = importlib.util.find_spec("pyhanko")   is not None
_REPORTLAB_AVAILABLE = importlib.util.find_spec("reportlab") is not None


# ── Self-signed certificate generation ───────────────────────────────────────

def _generate_self_signed_p12(p12_path: Path, passphrase: bytes = b"") -> None:
    """
    Generate a self-signed RSA-2048 certificate and save it as PKCS#12.
    Only called when GUARDRAIL_SIGNING_KEY_P12 is not set.
    The resulting key is suitable for development / testing only.
    """
    import datetime as _dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.serialization.pkcs12 import serialize_key_and_certificates
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,       "Guardrail Framework Report Signer"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Guardrail Framework"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,      "US"),
    ])
    now = _dt.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    enc = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase else serialization.NoEncryption()
    )
    p12_bytes = serialize_key_and_certificates(
        name=b"guardrail-report-signer",
        key=key, cert=cert, cas=None,
        encryption_algorithm=enc,
    )
    p12_path.write_bytes(p12_bytes)
    logger.warning(
        "Auto-generated a self-signed dev signing key at %s  "
        "— NOT suitable for production. Set GUARDRAIL_SIGNING_KEY_P12 "
        "to a production-issued PKCS#12 certificate.",
        p12_path,
    )


# ── OWASP label map (shared with PDF renderer) ────────────────────────────────

_OWASP_LABELS: Dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model DoS",
    "LLM05": "Supply Chain",
    "LLM06": "Sensitive Info Disclosure",
    "LLM07": "Insecure Plugin",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft",
}


# ── Main class ────────────────────────────────────────────────────────────────

class ReportSigner:
    """
    Generates signed PDFs from red-team reports and verifies their integrity.

    Instantiate once per process.  The PKCS#12 signing key is loaded (or
    auto-generated) lazily on the first call to generate_signed_report.
    """

    def __init__(self, audit_shipper=None):
        if not _PYHANKO_AVAILABLE:
            raise ImportError(
                "pyhanko is required. "
                "Install: pip install pyhanko pyhanko-certvalidator"
            )
        if not _REPORTLAB_AVAILABLE:
            raise ImportError(
                "reportlab is required. Install: pip install reportlab"
            )
        self._shipper = audit_shipper
        self._tsa_url = os.getenv("GUARDRAIL_TSA_URL", "http://freetsa.org/tsr")
        self._p12_path = os.getenv("GUARDRAIL_SIGNING_KEY_P12", "")
        self._pass = os.getenv("GUARDRAIL_SIGNING_KEY_PASS", "").encode()
        self._signer = None  # lazy-loaded on first sign

    # ── Private helpers ───────────────────────────────────────────────────────

    def _ensure_p12(self) -> str:
        if self._p12_path and Path(self._p12_path).exists():
            return self._p12_path
        auto = Path("guardrail_signing.p12")
        if not auto.exists():
            _generate_self_signed_p12(auto, self._pass)
        return str(auto)

    def _get_signer(self):
        from pyhanko.sign import signers as _signers
        if self._signer is None:
            p12 = self._ensure_p12()
            self._signer = _signers.SimpleSigner.load_pkcs12(
                p12, passphrase=self._pass if self._pass else None
            )
        return self._signer

    @staticmethod
    def _hash_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _audit_export(self, sha256: str, run_id: str, out_path: str) -> None:
        if self._shipper is None:
            return
        from guardrail_framework.decision_log import DecisionEvent
        self._shipper.enqueue(DecisionEvent(
            check_type="report_export",
            policy_name="report_signer",
            passed=True,
            user_context={
                "sha256": sha256,
                "run_id": run_id,
                "path": out_path,
            },
        ))

    # ── PDF generation (reportlab) ────────────────────────────────────────────

    def _build_pdf(self, report: Any, path: Path) -> None:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER  # noqa: F401
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )

        is_comparison = hasattr(report, "backends_tested")
        run_id = report.run_id

        doc = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            title=f"Red Team Report — {run_id}",
            author="Guardrail Framework",
            subject=f"run_id={run_id}",
            keywords=f"run_id={run_id}",
            leftMargin=20 * mm, rightMargin=20 * mm,
            topMargin=20 * mm, bottomMargin=20 * mm,
        )

        styles = getSampleStyleSheet()
        H1 = ParagraphStyle("rh1", parent=styles["Title"],    fontSize=17, spaceAfter=5)
        H2 = ParagraphStyle("rh2", parent=styles["Heading2"], fontSize=11, spaceBefore=8, spaceAfter=3)
        BL = ParagraphStyle("rbl", parent=styles["Normal"],   fontSize=8,  leading=13)

        _BG  = colors.HexColor("#1e293b")   # header bg
        _GRN = colors.HexColor("#10b981")   # green
        _RED = colors.HexColor("#ef4444")   # red
        _AMB = colors.HexColor("#f59e0b")   # amber
        _WT  = colors.white
        _R1  = colors.HexColor("#f8fafc")   # row alt 1
        _GRD = colors.HexColor("#cbd5e1")   # grid colour

        def _pass_color(rate: float):
            return _GRN if rate >= 0.8 else (_AMB if rate >= 0.5 else _RED)

        def _base_style(n_cols: int) -> list:
            return [
                ("BACKGROUND",    (0, 0), (n_cols - 1, 0), _BG),
                ("TEXTCOLOR",     (0, 0), (n_cols - 1, 0), _WT),
                ("FONTNAME",      (0, 0), (n_cols - 1, 0), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_R1, _WT]),
                ("GRID",          (0, 0), (-1, -1), 0.4, _GRD),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING",   (0, 0), (-1, -1), 5),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
            ]

        story: list = []

        # ── Title ──────────────────────────────────────────────────────────────
        report_kind = "Backend Comparison" if is_comparison else "Single Backend"
        story.append(Paragraph(f"Red Team Security Report ({report_kind})", H1))
        story.append(Spacer(1, 3 * mm))

        # ── Metadata block ─────────────────────────────────────────────────────
        def _backend_str(b: Any) -> str:
            return b.value if hasattr(b, "value") else str(b)

        meta_rows: list = [
            ["Run ID",    run_id],
            ["Timestamp", str(report.timestamp)],
            ["Generated", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")],
        ]
        if is_comparison:
            meta_rows += [
                ["Backends tested", ", ".join(_backend_str(b) for b in report.backends_tested)],
                ["Best overall",    str(report.best_overall)],
                ["Worst overall",   str(report.worst_overall)],
            ]
        else:
            meta_rows += [
                ["Backend",          _backend_str(report.backend)],
                ["Total probes",     str(report.total_probes)],
                ["Passed / Failed",  f"{report.passed} / {report.failed}"],
                ["Pass rate",        f"{report.pass_rate * 100:.1f}%"],
                ["Avg latency",      f"{report.average_latency_ms:.1f} ms"],
            ]

        meta_tbl = Table(meta_rows, colWidths=[44 * mm, 116 * mm])
        meta_tbl.setStyle(TableStyle([
            ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE",  (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_R1, _WT]),
            ("GRID",      (0, 0), (-1, -1), 0.4, _GRD),
            ("VALIGN",    (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ]))
        story.append(meta_tbl)
        story.append(Spacer(1, 5 * mm))

        # ── Per-category breakdown (single-backend only) ───────────────────────
        if not is_comparison:
            story.append(Paragraph("Results by OWASP Category", H2))

            cat_rows = [["OWASP", "Category", "Total", "Passed", "Failed", "Pass %"]]
            for ref in sorted(report.results_by_category.keys()):
                cat = report.results_by_category[ref]
                rate = cat.get("pass_rate", 0)
                cat_rows.append([
                    ref,
                    _OWASP_LABELS.get(ref, ref),
                    str(cat.get("total", 0)),
                    str(cat.get("passed", 0)),
                    str(cat.get("failed", 0)),
                    f"{rate * 100:.0f}%",
                ])

            col_w = [14 * mm, 52 * mm, 17 * mm, 17 * mm, 17 * mm, 17 * mm]
            cat_tbl = Table(cat_rows, colWidths=col_w)
            cat_style = _base_style(6)
            for i, row in enumerate(cat_rows[1:], 1):
                try:
                    rate_val = float(row[5].rstrip("%")) / 100
                except ValueError:
                    rate_val = 0.0
                cat_style += [
                    ("TEXTCOLOR", (5, i), (5, i), _pass_color(rate_val)),
                    ("FONTNAME",  (5, i), (5, i), "Helvetica-Bold"),
                ]
            cat_tbl.setStyle(TableStyle(cat_style))
            story.append(cat_tbl)
            story.append(Spacer(1, 4 * mm))

            # Severity breakdown
            story.append(Paragraph("Results by Severity", H2))
            sev_rows = [["Severity", "Total", "Passed", "Failed", "Pass %"]]
            for sev in ("critical", "high", "medium", "low"):
                d = report.results_by_severity.get(sev)
                if d and d.get("total", 0):
                    rate = d.get("pass_rate", 0)
                    sev_rows.append([
                        sev.upper(),
                        str(d.get("total", 0)),
                        str(d.get("passed", 0)),
                        str(d.get("failed", 0)),
                        f"{rate * 100:.0f}%",
                    ])
            sev_tbl = Table(sev_rows, colWidths=[28 * mm] * 5)
            sev_tbl.setStyle(TableStyle(_base_style(5)))
            story.append(sev_tbl)

        # ── Comparison tables ─────────────────────────────────────────────────
        else:
            story.append(Paragraph("Backend Comparison Summary", H2))
            comp_rows = [["Backend", "Total", "Passed", "Failed", "Pass %", "Avg ms"]]
            for b in report.backends_tested:
                bv = _backend_str(b)
                rep = report.reports.get(bv)
                if not rep:
                    continue
                rate = rep.pass_rate
                label = bv.replace("_", " ")
                if bv == report.best_overall:
                    label += " ★"   # ★ best
                comp_rows.append([
                    label,
                    str(rep.total_probes),
                    str(rep.passed),
                    str(rep.failed),
                    f"{rate * 100:.1f}%",
                    f"{rep.average_latency_ms:.0f}",
                ])
            comp_tbl = Table(comp_rows, colWidths=[42 * mm, 18 * mm, 18 * mm, 18 * mm, 22 * mm, 18 * mm])
            comp_style = _base_style(6)
            for i, row in enumerate(comp_rows[1:], 1):
                try:
                    rate_val = float(row[4].rstrip("%")) / 100
                except ValueError:
                    rate_val = 0.0
                comp_style += [
                    ("TEXTCOLOR", (4, i), (4, i), _pass_color(rate_val)),
                    ("FONTNAME",  (4, i), (4, i), "Helvetica-Bold"),
                ]
            comp_tbl.setStyle(TableStyle(comp_style))
            story.append(comp_tbl)
            story.append(Spacer(1, 4 * mm))

            # Category winners
            story.append(Paragraph("Category Winners", H2))
            winner_rows = [["OWASP Ref", "Category", "Winner Backend"]]
            for ref in sorted(report.category_winners.keys()):
                winner_rows.append([
                    ref,
                    _OWASP_LABELS.get(ref, ref),
                    str(report.category_winners[ref]).replace("_", " "),
                ])
            winner_tbl = Table(winner_rows, colWidths=[16 * mm, 60 * mm, 60 * mm])
            winner_tbl.setStyle(TableStyle(_base_style(3)))
            story.append(winner_tbl)

        # ── Footer ─────────────────────────────────────────────────────────────
        story.append(Spacer(1, 10 * mm))
        story.append(Paragraph(
            "This document is digitally signed with an electronic signature "
            "and an RFC 3161 trusted timestamp. "
            "Verify the signature using any PDF viewer or via the "
            f"GET /redteam/reports/{run_id}/export endpoint.",
            BL,
        ))

        doc.build(story)

    # ── PDF signing (pyhanko) ─────────────────────────────────────────────────

    def _sign_pdf(self, unsigned: Path, signed: Path) -> None:
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign import fields as _fields
        from pyhanko.sign import signers as _signers
        from pyhanko.sign.timestamps import HTTPTimeStamper

        signer = self._get_signer()
        sig_field_name = "Signature1"
        # Position the visible signature stamp in the lower-left of page 0
        sig_box = (10, 10, 260, 60)

        def _attempt(use_tsa: bool) -> bytes:
            ts = HTTPTimeStamper(self._tsa_url) if use_tsa else None
            with open(unsigned, "rb") as inf:
                writer = IncrementalPdfFileWriter(inf)
                _fields.append_signature_field(
                    writer,
                    sig_field_spec=_fields.SigFieldSpec(
                        sig_field_name, on_page=0, box=sig_box
                    ),
                )
                meta = _signers.PdfSignatureMetadata(
                    field_name=sig_field_name,
                    reason="Guardrail Framework automated red-team report",
                    location="Guardrail Platform",
                )
                out = _signers.sign_pdf(
                    writer, meta, signer=signer, timestamper=ts
                )
                out.seek(0)
                return out.read()

        try:
            data = _attempt(use_tsa=True)
        except Exception as tsa_err:
            logger.warning(
                "RFC 3161 timestamp from %s failed (%s); "
                "signing without trusted timestamp",
                self._tsa_url, tsa_err,
            )
            data = _attempt(use_tsa=False)

        signed.write_bytes(data)

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_signed_report(self, report: Any, output_path) -> Path:
        """
        Generate and sign a PDF report.

        Parameters
        ----------
        report:
            RedTeamReport or ComparisonReport dataclass instance.
        output_path:
            Destination for the signed PDF file.

        Returns
        -------
        Path
            Resolved path to the signed PDF.

        Side effects
        ------------
        Enqueues a ``DecisionEvent`` to the audit shipper (if configured)
        containing the SHA-256 hash of the signed PDF.
        """
        out = Path(output_path)
        unsigned = out.with_suffix(".unsigned.pdf")
        try:
            self._build_pdf(report, unsigned)
            self._sign_pdf(unsigned, out)
        finally:
            try:
                unsigned.unlink()
            except FileNotFoundError:
                pass

        sha256 = self._hash_file(out)
        self._audit_export(sha256, report.run_id, str(out))
        logger.info("Signed report written: %s  sha256=%s…", out, sha256[:16])
        return out

    def verify_report(self, pdf_path) -> Dict[str, Any]:
        """
        Verify the embedded digital signature of a signed report PDF.

        Parameters
        ----------
        pdf_path:
            Path to the signed PDF file.

        Returns
        -------
        dict with keys:
            valid (bool)               – True iff signature intact and cert trusted.
            signed_at (datetime|None)  – RFC 3161 timestamp, or signer-reported time.
            run_id (str|None)          – Extracted from the PDF Keywords/Subject field.
        """
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import validate_pdf_signature
        from pyhanko_certvalidator import ValidationContext

        pdf_path = Path(pdf_path)
        result: Dict[str, Any] = {"valid": False, "signed_at": None, "run_id": None}

        with open(pdf_path, "rb") as fh:
            r = PdfFileReader(fh)

            # ── Extract run_id from PDF info dict ──────────────────────────────
            try:
                info_ref = r.trailer.get("/Info")
                if info_ref is not None:
                    info_obj = info_ref.get_object()
                    for key in ("/Subject", "/Keywords"):
                        raw = info_obj.get(key)
                        if raw is None:
                            continue
                        text = (
                            raw.decode("utf-8", errors="replace")
                            if isinstance(raw, (bytes, bytearray))
                            else str(raw)
                        )
                        m = re.search(r"run_id=([a-f0-9\-]{32,36})", text)
                        if m:
                            result["run_id"] = m.group(1)
                            break
            except Exception:
                pass

            # ── Validate signature ─────────────────────────────────────────────
            sigs = r.embedded_signatures
            if not sigs:
                result["detail"] = "No embedded signatures found"
                return result

            sig = sigs[0]
            try:
                # Use the embedded signer cert as the trust root.
                # For production, replace with your organisation's CA cert.
                signer_cert = sig.signer_cert
                vc = ValidationContext(
                    trust_roots=[signer_cert],
                    allow_fetching=False,
                )
                status = validate_pdf_signature(sig, vc)
                result["valid"] = bool(
                    getattr(status, "valid",  False)
                    and getattr(status, "intact", False)
                )

                # Prefer RFC 3161 timestamp; fall back to signer-reported time
                ts_status = getattr(status, "timestamp_validity", None)
                if ts_status is not None and getattr(ts_status, "valid", False):
                    ts = getattr(ts_status, "timestamp", None)
                    if ts is not None:
                        result["signed_at"] = ts.astimezone(timezone.utc)
                if result["signed_at"] is None:
                    dt = getattr(status, "signer_reported_dt", None)
                    if dt is not None:
                        result["signed_at"] = dt.astimezone(timezone.utc)

            except Exception as exc:
                result["valid"] = False
                result["detail"] = str(exc)

        return result
