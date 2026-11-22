import json

from tracecase.core.database import get_connection
from tracecase.core.validators import (
    generate_id,
    utc_now,
    validate_required_text,
    validate_json_object,
)


def create_event(
    case_id: str,
    event_type: str,
    description: str,
    actor: str,
    target_id: str | None = None,
    run_id: str | None = None,
    finding_id: str | None = None,
    evidence_reference: str | None = None,
    event_data: dict | None = None,
):
    event_id = generate_id()
    created_at = utc_now()

    event_type = validate_required_text(
        event_type, "event_type", 100
    )
    description = validate_required_text(
        description, "description", 2000
    )
    actor = validate_required_text(actor, "actor", 200)

    event_data = validate_json_object(
        event_data or {}
    )

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO case_events (
                event_id,
                case_id,
                target_id,
                run_id,
                finding_id,
                evidence_reference,
                event_type,
                description,
                event_data_json,
                actor,
                created_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                case_id,
                target_id,
                run_id,
                finding_id,
                evidence_reference,
                event_type,
                description,
                json.dumps(event_data),
                actor,
                created_at,
            ),
        )

        connection.commit()

        row = connection.execute(
            """
            SELECT *
            FROM case_events
            WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()

        return dict(row)

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_event(event_id: str):
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM case_events
            WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()

        return dict(row) if row else None

    finally:
        connection.close()


def list_case_events(
    case_id: str,
    limit: int = 500,
):
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM case_events
            WHERE case_id = ?
            ORDER BY created_at_utc ASC, event_id ASC
            LIMIT ?
            """,
            (case_id, limit),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()