from tracecase.core.database import get_connection


def get_case_report_data(case_id: str) -> dict:
    """Return complete report data for a case."""

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

        return {
            "case": dict(case_row),
            "targets": [dict(row) for row in targets],
            "runs": [dict(row) for row in runs],
            "findings": [dict(row) for row in findings],
            "evidence": [dict(row) for row in evidence],
            "events": [dict(row) for row in events],
        }

    finally:
        connection.close()