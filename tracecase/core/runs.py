
import sqlite3

from tracecase.contracts import OperationType, OperationStatus, ExecutionMode
from tracecase.core.database import get_connection
from tracecase.core.validators import (
    generate_id,
    utc_now,
    validate_required_text,
    validate_enum,
)


def create_run(data):
    run_id = generate_id()
    created_at = utc_now()

    case_id = validate_required_text(data.case_id, "case_id")
    target_id = data.target_id

    operation_type = validate_enum(
        data.operation_type,
        OperationType,
    )

    execution_mode = (
        validate_enum(data.execution_mode, ExecutionMode)
        if data.execution_mode is not None
        else None
    )

    status = validate_enum(
        data.status,
        OperationStatus,
    )

    summary = data.summary
    error_summary = data.error_summary

    connection = get_connection()

    try:
        case = connection.execute(
            "SELECT case_id FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()

        if case is None:
            raise ValueError("Case does not exist")

        if target_id is not None:
            target = connection.execute(
                """
                SELECT target_id
                FROM targets
                WHERE target_id = ? AND case_id = ?
                """,
                (target_id, case_id),
            ).fetchone()

            if target is None:
                raise ValueError("Target does not belong to this case")

        connection.execute(
            """
            INSERT INTO investigation_runs (
                run_id, case_id, target_id, operation_type,
                execution_mode, status, summary, error_summary,
                created_at_utc, started_at_utc, completed_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                case_id,
                target_id,
                operation_type,
                execution_mode,
                status,
                summary,
                error_summary,
                created_at,
                None,
                None,
            ),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return get_run(case_id, run_id)


def update_run_status(
    run_id,
    status,
    *,
    summary=None,
    error_summary=None,
):
    status = validate_enum(status, OperationStatus)
    updated_at = utc_now()

    connection = get_connection()

    try:
        run = connection.execute(
            "SELECT * FROM investigation_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()

        if run is None:
            raise ValueError("Run does not exist")

        connection.execute(
            """
            UPDATE investigation_runs
            SET status = ?,
                summary = COALESCE(?, summary),
                error_summary = COALESCE(?, error_summary),
                completed_at_utc = ?
            WHERE run_id = ?
            """,
            (
                status,
                summary,
                error_summary,
                updated_at if status in (
                    OperationStatus.SUCCESS,
                    OperationStatus.PARTIAL,
                    OperationStatus.FAILED,
                    OperationStatus.CANCELLED,
                ) else None,
                run_id,
            ),
        )

        connection.commit()

        case_id = run["case_id"]

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    return get_run(case_id, run_id)


def get_run(case_id, run_id):
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM investigation_runs
            WHERE case_id = ? AND run_id = ?
            """,
            (case_id, run_id),
        ).fetchone()

        return dict(row) if row else None

    finally:
        connection.close()


def list_runs(case_id, target_id=None):
    connection = get_connection()

    try:
        if target_id is None:
            rows = connection.execute(
                """
                SELECT *
                FROM investigation_runs
                WHERE case_id = ?
                ORDER BY created_at_utc DESC
                """,
                (case_id,),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT *
                FROM investigation_runs
                WHERE case_id = ? AND target_id = ?
                ORDER BY created_at_utc DESC
                """,
                (case_id, target_id),
            ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
