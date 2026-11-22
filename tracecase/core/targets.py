import sqlite3

from tracecase.contracts import TargetCreate, Target
from tracecase.core.database import get_connection
from tracecase.core.validators import (
    generate_id,
    utc_now,
    validate_indicator,
    validate_enum,
    validate_required_text,
)


def create_target(case_id: str, data: TargetCreate) -> Target:
    connection = get_connection()

    try:
        case = connection.execute(
            "SELECT case_id, status FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()

        if case is None:
            raise ValueError("Case not found")

        if case["status"] == "closed":
            raise ValueError("Cannot add targets to a closed case")

        indicator = validate_indicator(
            data.indicator,
            data.indicator_type,
        )

        indicator_type = validate_enum(
            data.indicator_type,
            type(data.indicator_type),
        )

        target_kind = validate_enum(
            data.target_kind,
            type(data.target_kind),
        )

        target_id = generate_id()
        created_at = utc_now()

        connection.execute(
            """
            INSERT INTO targets (
                target_id,
                case_id,
                indicator,
                indicator_type,
                target_kind,
                display_name,
                active_testing_authorized,
                scope_note,
                authorization_note,
                authorization_expires_at_utc,
                notes,
                created_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target_id,
                case_id,
                indicator,
                indicator_type,
                target_kind,
                getattr(data, "display_name", None),
                int(getattr(data, "active_testing_authorized", False)),
                getattr(data, "scope_note", None),
                getattr(data, "authorization_note", None),
                getattr(data, "authorization_expires_at_utc", None),
                getattr(data, "notes", None),
                created_at,
            ),
        )

        connection.commit()

        row = connection.execute(
            """
            SELECT *
            FROM targets
            WHERE target_id = ? AND case_id = ?
            """,
            (target_id, case_id),
        ).fetchone()

        return Target(**dict(row))

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_target(case_id: str, target_id: str) -> Target | None:
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM targets
            WHERE case_id = ? AND target_id = ?
            """,
            (case_id, target_id),
        ).fetchone()

        if row is None:
            return None

        return Target(**dict(row))

    finally:
        connection.close()


def list_targets(case_id: str) -> list[Target]:
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM targets
            WHERE case_id = ?
            ORDER BY created_at_utc DESC
            """,
            (case_id,),
        ).fetchall()

        return [Target(**dict(row)) for row in rows]

    finally:
        connection.close()