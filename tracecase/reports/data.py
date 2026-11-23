
import json
from datetime import datetime, timezone

from tracecase.core.database import get_connection


def _decode_limitations(value: str | None) -> list[str]:
    """Decode a finding's stored limitations JSON safely."""
    if not value:
        return []

    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []

    if not isinstance(decoded, list):
        return []

    return [
        item.strip()
        for item in decoded
        if isinstance(item, str) and item.strip()
    ]


def get_case_report_data(case_id: str) -> dict:
    """Prepare the canonical report data for one investigation case."""

    connection = get_connection()

    try:
        case_row = connection.execute(
            """
            SELECT *
            FROM cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

        if case_row is None:
            raise ValueError("Case not found")

        targets = connection.execute(
            """
            SELECT *
            FROM targets
            WHERE case_id = ?
            ORDER BY created_at_utc
            """,
            (case_id,),
        ).fetchall()

        runs = connection.execute(
            """
            SELECT *
            FROM investigation_runs
            WHERE case_id = ?
            ORDER BY created_at_utc
            """,
            (case_id,),
        ).fetchall()

        findings = connection.execute(
            """
            SELECT *
            FROM findings
            WHERE case_id = ?
            ORDER BY collected_at_utc
            """,
            (case_id,),
        ).fetchall()

        evidence = connection.execute(
            """
            SELECT *
            FROM evidence
            WHERE case_id = ?
            ORDER BY received_at_utc
            """,
            (case_id,),
        ).fetchall()

        events = connection.execute(
            """
            SELECT *
            FROM case_events
            WHERE case_id = ?
            ORDER BY created_at_utc
            """,
            (case_id,),
        ).fetchall()

        case_data = dict(case_row)
        target_data = [dict(row) for row in targets]
        run_data = [dict(row) for row in runs]
        finding_data = [dict(row) for row in findings]
        evidence_data = [dict(row) for row in evidence]
        event_data = [dict(row) for row in events]

        # Collect limitations actually recorded in findings.
        limitations = []
        seen_limitations = set()

        for finding in finding_data:
            for limitation in _decode_limitations(
                finding.get("limitations_json")
            ):
                if limitation not in seen_limitations:
                    limitations.append(limitation)
                    seen_limitations.add(limitation)

        # Preserve source attribution from actual findings and evidence.
        source_attribution = []
        seen_sources = set()

        for finding in finding_data:
            attribution = {
                "record_type": "finding",
                "finding_id": finding["finding_id"],
                "source": finding["source"],
                "source_url": finding["source_url"],
                "source_tool": None,
            }

            source_key = (
                attribution["record_type"],
                attribution["finding_id"],
            )

            if source_key not in seen_sources:
                source_attribution.append(attribution)
                seen_sources.add(source_key)

        for item in evidence_data:
            attribution = {
                "record_type": "evidence",
                "evidence_reference": item["evidence_reference"],
                "source": None,
                "source_url": None,
                "source_tool": item["source_tool"],
            }

            source_key = (
                attribution["record_type"],
                attribution["evidence_reference"],
            )

            if source_key not in seen_sources:
                source_attribution.append(attribution)
                seen_sources.add(source_key)

        return {
            "generated_at_utc": (
                datetime.now(timezone.utc)
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            ),
            "case": case_data,
            "scope": case_data["scope_description"],
            "targets": target_data,
            "investigation_runs": run_data,
            "findings": finding_data,
            "evidence": evidence_data,
            "timeline_events": event_data,
            "limitations": limitations,
            "source_attribution": source_attribution,
            "summary_counts": {
                "targets": len(target_data),
                "investigation_runs": len(run_data),
                "findings": len(finding_data),
                "evidence": len(evidence_data),
                "timeline_events": len(event_data),
            },
        }

    finally:
        connection.close()
