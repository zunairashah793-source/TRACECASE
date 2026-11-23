
import json

from contextlib import contextmanager
from datetime import datetime, timezone

from tracecase.contracts import (
    CaseStatus,
    TargetKind,
    OperationType,
    ExecutionMode,
    OperationStatus,
)

from tracecase.core.database import get_connection

from tracecase.core.validators import (
    generate_id,
    utc_now,
    validate_required_text,
    validate_json_object,
    validate_utc_timestamp,
)


@contextmanager
def _connection_scope():
    """Open a database connection and always close it."""
    connection = get_connection()

    try:
        yield connection
        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def _validate_operation_type(value):
    try:
        return OperationType(value).value
    except (ValueError, TypeError):
        raise ValueError("Invalid operation type")


def _validate_execution_mode(value):
    try:
        return ExecutionMode(value).value
    except (ValueError, TypeError):
        raise ValueError("Invalid execution mode")


def _validate_operation_status(value):
    try:
        return OperationStatus(value).value
    except (ValueError, TypeError):
        raise ValueError("Invalid operation status")


def _check_case_open(connection, case_id):
    case = connection.execute(
        """
        SELECT case_id, status
        FROM cases
        WHERE case_id = ?
        """,
        (case_id,),
    ).fetchone()

    if case is None:
        raise ValueError("Case not found")

    if case["status"] != CaseStatus.OPEN.value:
        raise ValueError("Cannot operate on a closed case")

    return case


def _get_target(connection, case_id, target_id):
    target = connection.execute(
        """
        SELECT *
        FROM targets
        WHERE case_id = ? AND target_id = ?
        """,
        (case_id, target_id),
    ).fetchone()

    if target is None:
        raise ValueError("Target not found in this case")

    return target


def _check_assessment_authorization(target):
    """Verify that a target is explicitly authorized for lab assessment."""

    if target["target_kind"] != TargetKind.AUTHORIZED_LAB.value:
        raise ValueError(
            "Authorized assessment requires an authorized lab target"
        )

    if not bool(target["active_testing_authorized"]):
        raise ValueError(
            "Active testing is not authorized for this target"
        )

    expiry = target["authorization_expires_at_utc"]

    if expiry:
        validate_utc_timestamp(expiry)

        expiry_datetime = datetime.strptime(
            expiry,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=timezone.utc)

        if expiry_datetime <= datetime.now(timezone.utc):
            raise ValueError("Target authorization has expired")


def _validate_operation_target(
    connection,
    case_id,
    target_id,
    operation_type,
):
    """Validate target presence, ownership and assessment authorization."""

    if operation_type == OperationType.CASE_EVIDENCE_IMPORT.value:

        if target_id is not None:
            raise ValueError(
                "Case evidence import must not specify a target"
            )

        return None

    if not target_id:
        raise ValueError(
            "target_id is required for this operation"
        )

    target = _get_target(
        connection,
        case_id,
        target_id,
    )

    if operation_type == OperationType.AUTHORIZED_ASSESSMENT.value:
        _check_assessment_authorization(target)

    return target


def _optional_text(value, field, max_length=5000):
    if value is None or value == "":
        return None

    return validate_required_text(
        value,
        field,
        max_length,
    )


def create_operation(
    case_id,
    target_id,
    operation_type,
    requested_by,
    execution_mode=None,
    input_summary=None,
):
    """Create a queued investigation operation."""

    operation_type = _validate_operation_type(operation_type)

    requested_by = validate_required_text(
        requested_by,
        "requested_by",
        200,
    )

    if operation_type == OperationType.AUTHORIZED_ASSESSMENT.value:

        if execution_mode is None:
            raise ValueError(
                "execution_mode is required for authorized assessment"
            )

        execution_mode = _validate_execution_mode(execution_mode)

    else:
        execution_mode = None

    if input_summary is None:
        input_summary = {}

    input_summary = validate_json_object(input_summary)

    input_summary_json = json.dumps(input_summary)

    run_id = generate_id()
    created_at = utc_now()

    with _connection_scope() as connection:

        _check_case_open(
            connection,
            case_id,
        )

        _validate_operation_target(
            connection,
            case_id,
            target_id,
            operation_type,
        )

        connection.execute(
            """
            INSERT INTO investigation_runs (
                run_id,
                case_id,
                target_id,
                operation_type,
                status,
                execution_mode,
                requested_by,
                input_summary_json,
                created_at_utc
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
                input_summary_json,
                created_at,
            ),
        )

    return run_id


def start_operation(run_id):
    """Start a queued operation after rechecking its authorization."""

    started_at = utc_now()

    with _connection_scope() as connection:

        operation = connection.execute(
            """
            SELECT *
            FROM investigation_runs
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        if operation is None:
            raise ValueError("Operation not found")

        if operation["status"] != OperationStatus.QUEUED.value:
            raise ValueError("Operation cannot be started")

        case_id = operation["case_id"]
        target_id = operation["target_id"]
        operation_type = operation["operation_type"]

        _check_case_open(
            connection,
            case_id,
        )

        _validate_operation_target(
            connection,
            case_id,
            target_id,
            operation_type,
        )

        result = connection.execute(
            """
            UPDATE investigation_runs
            SET status = ?,
                started_at_utc = ?
            WHERE run_id = ?
              AND status = ?
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
    """Complete a running operation with a terminal status."""

    status = _validate_operation_status(status)

    allowed_statuses = (
        OperationStatus.SUCCESS.value,
        OperationStatus.PARTIAL.value,
        OperationStatus.FAILED.value,
        OperationStatus.CANCELLED.value,
    )

    if status not in allowed_statuses:
        raise ValueError("Invalid completion status")

    outcome_summary = _optional_text(
        outcome_summary,
        "outcome_summary",
    )

    error_summary = _optional_text(
        error_summary,
        "error_summary",
    )

    completed_at = utc_now()

    with _connection_scope() as connection:

        result = connection.execute(
            """
            UPDATE investigation_runs
            SET status = ?,
                completed_at_utc = ?,
                outcome_summary = ?,
                error_summary = ?
            WHERE run_id = ?
              AND status = ?
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
    """Retrieve one investigation operation."""

    with _connection_scope() as connection:

        row = connection.execute(
            """
            SELECT *
            FROM investigation_runs
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

    return dict(row) if row else None


def list_operations(case_id):
    """Retrieve all operations belonging to a case."""

    with _connection_scope() as connection:

        rows = connection.execute(
            """
            SELECT *
            FROM investigation_runs
            WHERE case_id = ?
            ORDER BY created_at_utc DESC
            """,
            (case_id,),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]
