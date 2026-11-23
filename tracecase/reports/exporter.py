
from io import BytesIO, StringIO
import csv
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


def _safe_text(value) -> str:
    """Convert values to safe text for ReportLab Paragraph."""
    return escape(str(value if value is not None else ""))


def export_case_report(report_data: dict) -> bytes:
    """Generate a PDF investigation report from canonical report data."""

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="TRACECASE Investigation Report",
    )

    styles = getSampleStyleSheet()
    story = []

    case_data = report_data.get("case", {})

    story.append(
        Paragraph(
            "TRACECASE Investigation Report",
            styles["Title"],
        )
    )

    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            "Generated: "
            + datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            ),
            styles["Normal"],
        )
    )

    story.append(Spacer(1, 15))
    story.append(Paragraph("Case Information", styles["Heading2"]))

    case_rows = [
        ["Case ID", _safe_text(case_data.get("case_id", ""))],
        ["Title", _safe_text(case_data.get("title", ""))],
        ["Status", _safe_text(case_data.get("status", ""))],
        ["Scope", _safe_text(case_data.get("scope_description", ""))],
        ["Description", _safe_text(case_data.get("description", ""))],
    ]

    table = Table(case_rows, colWidths=[40 * mm, 125 * mm])
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 6),
        ])
    )

    story.append(table)
    story.append(Spacer(1, 15))

    # Investigation runs
    story.append(Paragraph("Investigation Runs", styles["Heading2"]))

    runs = report_data.get("runs", [])

    if runs:
        run_rows = [[
            "Run ID",
            "Operation",
            "Status",
            "Requested By",
            "Outcome",
        ]]

        for run in runs:
            run_rows.append([
                _safe_text(run.get("run_id", "")),
                _safe_text(run.get("operation_type", "")),
                _safe_text(run.get("status", "")),
                _safe_text(run.get("requested_by", "")),
                _safe_text(run.get("outcome_summary", "")),
            ])

        run_table = Table(run_rows, repeatRows=1)
        run_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243447")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(run_table)
    else:
        story.append(Paragraph("No investigation runs recorded.", styles["Normal"]))

    story.append(Spacer(1, 15))

    # Targets
    story.append(Paragraph("Targets", styles["Heading2"]))
    targets = report_data.get("targets", [])

    if targets:
        target_rows = [["Indicator", "Type", "Kind"]]

        for target in targets:
            target_rows.append([
                _safe_text(target.get("indicator", "")),
                _safe_text(target.get("indicator_type", "")),
                _safe_text(target.get("target_kind", "")),
            ])

        target_table = Table(target_rows, repeatRows=1)
        target_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243447")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(target_table)
    else:
        story.append(Paragraph("No targets recorded.", styles["Normal"]))

    story.append(Spacer(1, 15))

    # Findings
    story.append(Paragraph("Findings", styles["Heading2"]))
    findings = report_data.get("findings", [])

    if findings:
        for index, finding in enumerate(findings, start=1):
            story.append(
                Paragraph(f"Finding {index}", styles["Heading3"])
            )
            story.append(
                Paragraph(
                    _safe_text(finding.get("summary", "No summary")),
                    styles["Normal"],
                )
            )
            story.append(
                Paragraph(
                    "Category: " + _safe_text(finding.get("category", "")),
                    styles["Normal"],
                )
            )
            story.append(
                Paragraph(
                    "Confidence: " + _safe_text(finding.get("confidence", "")),
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("No findings recorded.", styles["Normal"]))

    story.append(Spacer(1, 15))

    # Evidence
    story.append(Paragraph("Evidence", styles["Heading2"]))
    evidence = report_data.get("evidence", [])

    if evidence:
        evidence_rows = [["Filename", "Type", "SHA-256"]]

        for item in evidence:
            evidence_rows.append([
                _safe_text(item.get("original_filename", "")),
                _safe_text(item.get("evidence_type", "")),
                _safe_text(item.get("sha256", "")),
            ])

        evidence_table = Table(evidence_rows, repeatRows=1)
        evidence_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#243447")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(evidence_table)
    else:
        story.append(Paragraph("No evidence recorded.", styles["Normal"]))

    story.append(Spacer(1, 15))

    # Case timeline
    story.append(Paragraph("Case Timeline", styles["Heading2"]))
    events = report_data.get("events", [])

    if events:
        for event in events:
            story.append(
                Paragraph(
                    _safe_text(event.get("created_at_utc", "")),
                    styles["Normal"],
                )
            )
            story.append(
                Paragraph(
                    _safe_text(event.get("description", "")),
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 5))
    else:
        story.append(
            Paragraph("No case events recorded.", styles["Normal"])
        )

    story.append(Spacer(1, 20))
    story.append(
        Paragraph(
            "Generated by TRACECASE. "
            "Investigative conclusions must be reviewed by an analyst.",
            styles["Italic"],
        )
    )

    document.build(story)
    buffer.seek(0)

    return buffer.getvalue()


def export_case_csv(report_data: dict) -> bytes:
    """Export the canonical case report data as UTF-8 CSV."""

    output = StringIO()
    writer = csv.writer(output)

    case_data = report_data.get("case", {})

    writer.writerow(["TRACECASE Investigation Report"])
    writer.writerow(["Case ID", case_data.get("case_id", "")])
    writer.writerow(["Title", case_data.get("title", "")])
    writer.writerow(["Status", case_data.get("status", "")])
    writer.writerow(["Scope", case_data.get("scope_description", "")])
    writer.writerow(["Description", case_data.get("description", "")])
    writer.writerow([])

    # Investigation runs
    writer.writerow(["INVESTIGATION RUNS"])
    writer.writerow([
        "Run ID",
        "Operation",
        "Status",
        "Execution Mode",
        "Requested By",
        "Started",
        "Completed",
        "Outcome",
        "Error",
    ])

    for run in report_data.get("runs", []):
        writer.writerow([
            run.get("run_id", ""),
            run.get("operation_type", ""),
            run.get("status", ""),
            run.get("execution_mode", ""),
            run.get("requested_by", ""),
            run.get("started_at_utc", ""),
            run.get("completed_at_utc", ""),
            run.get("outcome_summary", ""),
            run.get("error_summary", ""),
        ])

    writer.writerow([])

    # Targets
    writer.writerow(["TARGETS"])
    writer.writerow(["Indicator", "Type", "Kind"])

    for target in report_data.get("targets", []):
        writer.writerow([
            target.get("indicator", ""),
            target.get("indicator_type", ""),
            target.get("target_kind", ""),
        ])

    writer.writerow([])

    # Findings
    writer.writerow(["FINDINGS"])
    writer.writerow(["Summary", "Category", "Confidence"])

    for finding in report_data.get("findings", []):
        writer.writerow([
            finding.get("summary", ""),
            finding.get("category", ""),
            finding.get("confidence", ""),
        ])

    writer.writerow([])

    # Evidence
    writer.writerow(["EVIDENCE"])
    writer.writerow(["Filename", "Type", "SHA-256"])

    for item in report_data.get("evidence", []):
        writer.writerow([
            item.get("original_filename", ""),
            item.get("evidence_type", ""),
            item.get("sha256", ""),
        ])

    writer.writerow([])

    # Timeline
    writer.writerow(["CASE TIMELINE"])
    writer.writerow(["Timestamp", "Description"])

    for event in report_data.get("events", []):
        writer.writerow([
            event.get("created_at_utc", ""),
            event.get("description", ""),
        ])

    return output.getvalue().encode("utf-8-sig")
