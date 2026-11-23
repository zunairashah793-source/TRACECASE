from io import BytesIO
from datetime import datetime, timezone

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


def export_case_report(report_data: dict) -> bytes:
    """
    Generate a PDF case report.

    Input:
        report_data: dictionary returned by the report data module.

    Output:
        PDF file bytes.
    """

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

    case_data = report_data.get("case", {})

    story.append(
        Paragraph("Case Information", styles["Heading2"])
    )

    case_rows = [
        ["Case ID", str(case_data.get("case_id", ""))],
        ["Title", str(case_data.get("title", ""))],
        ["Status", str(case_data.get("status", ""))],
        [
            "Scope",
            str(case_data.get("scope_description", "")),
        ],
        [
            "Description",
            str(case_data.get("description", "")),
        ],
    ]

    table = Table(
        case_rows,
        colWidths=[40 * mm, 125 * mm],
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(table)
    story.append(Spacer(1, 15))

    targets = report_data.get("targets", [])

    story.append(
        Paragraph("Targets", styles["Heading2"])
    )

    if targets:
        target_rows = [
            ["Indicator", "Type", "Kind"]
        ]

        for target in targets:
            target_rows.append(
                [
                    str(target.get("indicator", "")),
                    str(target.get("indicator_type", "")),
                    str(target.get("target_kind", "")),
                ]
            )

        target_table = Table(
            target_rows,
            repeatRows=1,
        )

        target_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#243447"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "PADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        story.append(target_table)

    else:
        story.append(
            Paragraph(
                "No targets recorded.",
                styles["Normal"],
            )
        )

    story.append(Spacer(1, 15))

    findings = report_data.get("findings", [])

    story.append(
        Paragraph("Findings", styles["Heading2"])
    )

    if findings:
        for index, finding in enumerate(findings, start=1):
            story.append(
                Paragraph(
                    f"Finding {index}",
                    styles["Heading3"],
                )
            )

            story.append(
                Paragraph(
                    str(finding.get("summary", "No summary")),
                    styles["Normal"],
                )
            )

            story.append(
                Paragraph(
                    "Category: "
                    + str(finding.get("category", "")),
                    styles["Normal"],
                )
            )

            story.append(
                Paragraph(
                    "Confidence: "
                    + str(finding.get("confidence", "")),
                    styles["Normal"],
                )
            )

            story.append(Spacer(1, 8))

    else:
        story.append(
            Paragraph(
                "No findings recorded.",
                styles["Normal"],
            )
        )

    story.append(Spacer(1, 15))

    evidence = report_data.get("evidence", [])

    story.append(
        Paragraph("Evidence", styles["Heading2"])
    )

    if evidence:
        evidence_rows = [
            ["Filename", "Type", "SHA-256"]
        ]

        for item in evidence:
            evidence_rows.append(
                [
                    str(item.get("original_filename", "")),
                    str(item.get("evidence_type", "")),
                    str(item.get("sha256", "")),
                ]
            )

        evidence_table = Table(
            evidence_rows,
            repeatRows=1,
        )

        evidence_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#243447"),
                    ),
                    (
                        "TEXTCOLOR",
                        (0, 0),
                        (-1, 0),
                        colors.white,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                    (
                        "PADDING",
                        (0, 0),
                        (-1, -1),
                        5,
                    ),
                ]
            )
        )

        story.append(evidence_table)

    else:
        story.append(
            Paragraph(
                "No evidence recorded.",
                styles["Normal"],
            )
        )

    story.append(Spacer(1, 15))

    events = report_data.get("events", [])

    story.append(
        Paragraph("Case Timeline", styles["Heading2"])
    )

    if events:
        for event in events:
            story.append(
                Paragraph(
                    str(event.get("created_at_utc", "")),
                    styles["Normal"],
                )
            )

            story.append(
                Paragraph(
                    str(event.get("description", "")),
                    styles["Normal"],
                )
            )

            story.append(Spacer(1, 5))

    else:
        story.append(
            Paragraph(
                "No case events recorded.",
                styles["Normal"],
            )
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