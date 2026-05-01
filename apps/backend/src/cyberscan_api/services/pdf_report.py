"""Render a scan report as PDF using ReportLab.

Pure function: takes plain dicts (so unit tests don't need ORM objects)
and returns the PDF bytes. The router wraps it in a StreamingResponse.
"""
from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

_SEV_COLORS = {
    "critical": colors.HexColor("#ef4444"),
    "high": colors.HexColor("#f97316"),
    "medium": colors.HexColor("#eab308"),
    "low": colors.HexColor("#3b82f6"),
    "info": colors.HexColor("#6b7280"),
}


def render(*, scan: dict[str, Any], asset: dict[str, Any], findings: list[dict[str, Any]]) -> bytes:
    """Return a PDF (as bytes) summarizing the scan and listing findings."""
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Cyberscan report — {asset.get('name')}",
        author="cyberscan",
    )

    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, textColor=colors.grey)

    story: list[Any] = []
    story.append(Paragraph(f"Cyberscan report — {asset.get('name', '')}", h1))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"Target: {asset.get('target_url', '')}", body))
    story.append(Paragraph(f"Scan ID: {scan.get('id', '')}", small))
    started = scan.get("started_at") or scan.get("created_at")
    finished = scan.get("finished_at")
    if started:
        story.append(Paragraph(f"Started: {_fmt(started)}", small))
    if finished:
        story.append(Paragraph(f"Finished: {_fmt(finished)}", small))
    story.append(Spacer(1, 6 * mm))

    # Summary block
    counts = (scan.get("summary") or {}).get("findings") or {}
    summary_rows = [
        ["Severity", "Count"],
        *[[s.title(), str(counts.get(s, 0))] for s in ("critical", "high", "medium", "low", "info")],
    ]
    summary_tbl = Table(summary_rows, colWidths=[60 * mm, 30 * mm])
    summary_tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#121826")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ]
        )
    )
    story.append(Paragraph("Summary", h2))
    story.append(summary_tbl)
    story.append(Spacer(1, 8 * mm))

    if not findings:
        story.append(Paragraph("No findings.", body))
        doc.build(story)
        return buf.getvalue()

    # Findings table — top 100 by risk score
    story.append(Paragraph("Findings (highest risk first)", h2))
    sorted_findings = sorted(
        findings,
        key=lambda f: (-(f.get("risk_score") or 0.0), f.get("severity", "info")),
    )

    table_rows: list[list[Any]] = [
        ["Severity", "Risk", "Title", "CVE(s)", "Location"],
    ]
    style_cmds: list[tuple[Any, ...]] = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#121826")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
    ]
    for i, f in enumerate(sorted_findings[:100], start=1):
        sev = (f.get("severity") or "info").lower()
        table_rows.append(
            [
                Paragraph(sev.upper(), small),
                f"{(f.get('risk_score') or 0.0):.1f}",
                Paragraph(f.get("title", ""), small),
                Paragraph(", ".join(f.get("cve_ids") or []) or "-", small),
                Paragraph(_truncate(f.get("location") or "-", 80), small),
            ]
        )
        style_cmds.append(
            ("BACKGROUND", (0, i), (0, i), _SEV_COLORS.get(sev, colors.grey))
        )
        style_cmds.append(("TEXTCOLOR", (0, i), (0, i), colors.white))

    findings_tbl = Table(
        table_rows,
        colWidths=[18 * mm, 14 * mm, 60 * mm, 36 * mm, 50 * mm],
        repeatRows=1,
    )
    findings_tbl.setStyle(TableStyle(style_cmds))
    story.append(findings_tbl)

    if len(sorted_findings) > 100:
        story.append(Spacer(1, 4 * mm))
        story.append(
            Paragraph(
                f"({len(sorted_findings) - 100} additional lower-risk findings omitted; "
                f"see CSV / JSON export for the complete list.)",
                small,
            )
        )

    # Per-finding remediation appendix (top 20)
    story.append(PageBreak())
    story.append(Paragraph("Remediation guidance — top findings", h2))
    for f in sorted_findings[:20]:
        story.append(Spacer(1, 3 * mm))
        story.append(
            Paragraph(
                f"<b>[{(f.get('severity') or 'info').upper()}] "
                f"risk {(f.get('risk_score') or 0):.1f}</b> — {f.get('title', '')}",
                body,
            )
        )
        if f.get("cve_ids"):
            story.append(Paragraph("CVE: " + ", ".join(f["cve_ids"]), small))
        if f.get("compliance_tags"):
            story.append(Paragraph("Compliance: " + " · ".join(f["compliance_tags"]), small))
        if f.get("remediation"):
            story.append(Paragraph(f["remediation"], body))

    doc.build(story)
    return buf.getvalue()


def _fmt(value: Any) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value)


def _truncate(value: str, n: int) -> str:
    return value if len(value) <= n else value[: n - 1] + "…"
