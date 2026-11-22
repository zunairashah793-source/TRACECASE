import json

from tracecase.contracts import OperationType, ExecutionMode, OperationStatus
from tracecase.core.database import get_connection
from tracecase.core.validators import generate_id, utc_now

def create_operation(
    case_id,
    target_id,
    operation_type,
    requested_by,
    execution_mode=None,
    input_summary=None,
):
    operation_type = OperationType(operation_type).value

    if operation_type == OperationType.AUTHORIZED_ASSESSMENT.value:
        if execution_mode is None:
            raise ValueError("execution_mode is required")
        execution_mode = ExecutionMode(execution_mode).value
    else:
        execution_mode = None

    run_id = generate_id()
    created_at = utc_now()

    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO investigation_runs (
                run_id, case_id, target_id, operation_type,
                status, execution_mode, requested_by,
                input_summary_json, created_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                case_id,
                target_id,
                operation_type,
                OperationStatus.QUEUED.value,
                execution_mode,
                requested_by,
                json.dumps(input_summary or {}),
                created_at,
            ),
        )

    return run_id

def start_operation(run_id):
    started_at = utc_now()

    with get_connection() as conn:
        result = conn.execute(
            """
            UPDATE investigation_runs
            SET status = ?, started_at_utc = ?
            WHERE run_id = ? AND status = ?
            """,
            (
                OperationStatus.RUNNING.value,
                started_at,
                run_id,
                OperationStatus.QUEUED.value,
            ),
        )

        if result.rowcount != 1:
            raise ValueError("Operation cannot be started")

    return started_at

def complete_operation(
    run_id,
    status,
    outcome_summary=None,
    error_summary=None,
):
    status = OperationStatus(status).value

    allowed_statuses = (
        OperationStatus.SUCCESS.value,
        OperationStatus.PARTIAL.value,
        OperationStatus.FAILED.value,
        OperationStatus.CANCELLED.value,
    )

    if status not in allowed_statuses:
        raise ValueError("Invalid completion status")

    completed_at = utc_now()

    with get_connection() as conn:
        result = conn.execute(
            """
            UPDATE investigation_runs
            SET status = ?,
                completed_at_utc = ?,
                outcome_summary = ?,
                error_summary = ?
            WHERE run_id = ? AND status = ?
            """,
            (
                status,
                completed_at,
                outcome_summary,
                error_summary,
                run_id,
                OperationStatus.RUNNING.value,
            ),
        )

        if result.rowcount != 1:
            raise ValueError("Operation cannot be completed")

    return completed_at

def get_operation(run_id):
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM investigation_runs
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

    return dict(row) if row else None

def list_operations(case_id):
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM investigation_runs
            WHERE case_id = ?
            ORDER BY created_at_utc DESC
            """,
            (case_id,),
        ).fetchall()

    return [dict(row) for row in rows]