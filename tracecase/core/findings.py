import json
import sqlite3

from tracecase.contracts import FindingPayload
from tracecase.core.database import get_connection
from tracecase.core.validators import (
    generate_id,
    utc_now,
    validate_uuid,
    validate_indicator,
    validate_json_object,
    validate_enum,
)


def create_finding(
    case_id: str,
    target_id: str,
    run_id: str,
    payload: FindingPayload,
    evidence_reference: str | None = None,
):
    case_id = validate_uuid(case_id)
    target_id = validate_uuid(target_id)
    run_id = validate_uuid(run_id)

    indicator = validate_indicator(
        payload.indicator,
        payload.indicator_type,
    )

    finding_id = generate_id()
    collected_at = payload.collected_at_utc
    validate_enum(payload.category, type(payload.category))
    validate_enum(payload.status, type(payload.status))
    validate_enum(payload.confidence, type(payload.confidence))

    finding_json = json.dumps(
        validate_json_object(payload.finding),
        sort_keys=True,
    )

    limitations_json = json.dumps(
        payload.limitations,
        ensure_ascii=False,
    )

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO findings (
                finding_id,
                case_id,
                target_id,
                run_id,
                indicator,
                indicator_type,
                category,
                source,
                collected_at_utc,
                status,
                summary,
                finding_json,
                confidence,
                limitations_json,
                source_url,
                evidence_reference
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                case_id,
                target_id,
                run_id,
                indicator,
                payload.indicator_type.value,
                payload.category.value,
                payload.source,
                collected_at,
                payload.status.value,
                payload.summary,
                finding_json,
                payload.confidence.value,
                limitations_json,
                payload.source_url,
                evidence_reference,
            ),
        )

        connection.commit()

        return get_finding(finding_id)

    except (sqlite3.Error, ValueError):
        connection.rollback()
        raise

    finally:
        connection.close()


def get_finding(finding_id: str):
    finding_id = validate_uuid(finding_id)

    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM findings
            WHERE finding_id = ?
            """,
            (finding_id,),
        ).fetchone()

        if row is None:
            return None

        result = dict(row)

        result["finding"] = json.loads(
            result.pop("finding_json")
        )

        result["limitations"] = json.loads(
            result.pop("limitations_json")
        )

        return result

    finally:
        connection.close()


def list_findings(
    case_id: str,
    target_id: str | None = None,
    run_id: str | None = None,
):
    case_id = validate_uuid(case_id)

    query = """
        SELECT *
        FROM findings
        WHERE case_id = ?
    """

    parameters = [case_id]

    if target_id is not None:
        target_id = validate_uuid(target_id)
        query += " AND target_id = ?"
        parameters.append(target_id)

    if run_id is not None:
        run_id = validate_uuid(run_id)
        query += " AND run_id = ?"
        parameters.append(run_id)

    query += " ORDER BY collected_at_utc DESC"

    connection = get_connection()

    try:
        rows = connection.execute(
            query,
            parameters,
        ).fetchall()

        results = []

        for row in rows:
            result = dict(row)

            result["finding"] = json.loads(
                result.pop("finding_json")
            )

            result["limitations"] = json.loads(
                result.pop("limitations_json")
            )

            results.append(result)

        return results

    finally:
        connection.close()