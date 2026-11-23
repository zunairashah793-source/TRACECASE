
from tracecase.contracts import CaseStatus
from tracecase.core.database import get_connection
from tracecase.core.validators import (
    generate_id,
    utc_now,
    validate_required_text,
)


def create_case(data):
    title = validate_required_text(data.title, "title", 200)
    scope_description = validate_required_text(
        data.scope_description, "scope_description", 5000
    )

    description = (
        validate_required_text(data.description, "description", 5000)
        if data.description else None
    )
    notes = (
        validate_required_text(data.notes, "notes", 5000)
        if data.notes else None
    )

    case_id = generate_id()
    now = utc_now()

    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO cases (
                case_id, title, description, scope_description,
                status, notes, created_at_utc, updated_at_utc,
                closed_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                case_id, title, description, scope_description,
                CaseStatus.OPEN.value, notes, now, now,
            ),
        )

        row = connection.execute(
            "SELECT * FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()

    return dict(row)


def get_case(case_id):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()

    return dict(row) if row else None


def list_cases(filters=None):
    query = "SELECT * FROM cases"
    params = []

    if filters and getattr(filters, "status", None):
        query += " WHERE status = ?"
        params.append(filters.status)

    query += " ORDER BY created_at_utc DESC"

    with get_connection() as connection:
        rows = connection.execute(query, params).fetchall()

    return [dict(row) for row in rows]


def update_case(data):
    case = get_case(data.case_id)

    if case is None:
        raise ValueError("Case not found")

    if case["status"] == CaseStatus.CLOSED.value:
        raise ValueError("Closed cases cannot be updated")

    title = validate_required_text(data.title, "title", 200)
    scope_description = validate_required_text(
        data.scope_description, "scope_description", 5000
    )

    description = (
        validate_required_text(data.description, "description", 5000)
        if data.description else None
    )
    notes = (
        validate_required_text(data.notes, "notes", 5000)
        if data.notes else None
    )

    now = utc_now()

    with get_connection() as connection:
        connection.execute(
            """
            UPDATE cases
            SET title = ?, description = ?, scope_description = ?,
                notes = ?, updated_at_utc = ?
            WHERE case_id = ?
            """,
            (
                title, description, scope_description,
                notes, now, data.case_id,
            ),
        )

    return get_case(data.case_id)


def close_case(case_id):
    case = get_case(case_id)

    if case is None:
        raise ValueError("Case not found")

    if case["status"] == CaseStatus.CLOSED.value:
        return case

    now = utc_now()

    with get_connection() as connection:
        connection.execute(
            """
            UPDATE cases
            SET status = ?, closed_at_utc = ?, updated_at_utc = ?
            WHERE case_id = ?
            """,
            (CaseStatus.CLOSED.value, now, now, case_id),
        )

    return get_case(case_id)
