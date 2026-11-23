
import pytest
from datetime import datetime, timedelta, timezone

from tracecase.core.database import initialize_database, get_connection
from tracecase.core.orchestration import (
    create_operation,
    start_operation,
    complete_operation,
    get_operation,
    list_operations,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    import tracecase.core.database as database

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "test_tracecase.sqlite3",
    )
    monkeypatch.setattr(
        database,
        "INSTANCE_DIR",
        tmp_path / "instance",
    )

    initialize_database()

    connection = get_connection()
    yield connection
    connection.close()


@pytest.fixture
def case_id(db):
    db.execute(
        """
        INSERT INTO cases (
            case_id, title, scope_description, status,
            created_at_utc, updated_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "case-001",
            "Test Case",
            "Authorized testing scope",
            "open",
            "2026-11-23T10:00:00Z",
            "2026-11-23T10:00:00Z",
        ),
    )
    db.commit()
    return "case-001"


@pytest.fixture
def lab_target(db, case_id):
    db.execute(
        """
        INSERT INTO targets (
            target_id, case_id, indicator, indicator_type,
            target_kind, active_testing_authorized,
            scope_note, authorization_note,
            authorization_expires_at_utc, created_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "target-001",
            case_id,
            "192.168.56.10",
            "ipv4",
            "authorized_lab",
            1,
            "Controlled private lab",
            "Approved laboratory exercise",
            "2099-12-31T23:59:59Z",
            "2026-11-23T10:00:00Z",
        ),
    )
    db.commit()
    return "target-001"


def test_create_queued_operation(db, case_id, lab_target):
    run_id = create_operation(
        case_id,
        lab_target,
        "authorized_assessment",
        "test-analyst",
        execution_mode="local",
        input_summary={"profile": "safe_test"},
    )

    operation = get_operation(run_id)

    assert operation is not None
    assert operation["status"] == "queued"
    assert operation["requested_by"] == "test-analyst"
    assert operation["execution_mode"] == "local"


def test_reject_missing_case(db):
    with pytest.raises(ValueError, match="Case not found"):
        create_operation(
            "missing-case",
            "target-001",
            "external_intelligence",
            "test-analyst",
        )


def test_reject_closed_case(db, case_id, lab_target):
    db.execute(
        "UPDATE cases SET status = 'closed' WHERE case_id = ?",
        (case_id,),
    )
    db.commit()

    with pytest.raises(ValueError, match="closed case"):
        create_operation(
            case_id,
            lab_target,
            "authorized_assessment",
            "test-analyst",
            execution_mode="local",
        )


def test_reject_target_from_another_case(db, case_id, lab_target):
    db.execute(
        """
        INSERT INTO cases (
            case_id, title, scope_description, status,
            created_at_utc, updated_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "case-002",
            "Another Case",
            "Another scope",
            "open",
            "2026-11-23T10:00:00Z",
            "2026-11-23T10:00:00Z",
        ),
    )
    db.commit()

    with pytest.raises(ValueError, match="Target not found"):
        create_operation(
            "case-002",
            lab_target,
            "authorized_assessment",
            "test-analyst",
            execution_mode="local",
        )


def test_reject_unauthorized_assessment(db, case_id):
    db.execute(
        """
        INSERT INTO targets (
            target_id, case_id, indicator, indicator_type,
            target_kind, active_testing_authorized,
            scope_note, created_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "target-002",
            case_id,
            "192.168.56.11",
            "ipv4",
            "authorized_lab",
            0,
            "Controlled lab",
            "2026-11-23T10:00:00Z",
        ),
    )
    db.commit()

    with pytest.raises(ValueError, match="not authorized"):
        create_operation(
            case_id,
            "target-002",
            "authorized_assessment",
            "test-analyst",
            execution_mode="local",
        )


def test_reject_expired_authorization(db, case_id):
    expired = (
        datetime.now(timezone.utc) - timedelta(days=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    db.execute(
        """
        INSERT INTO targets (
            target_id, case_id, indicator, indicator_type,
            target_kind, active_testing_authorized,
            scope_note, authorization_expires_at_utc,
            created_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "target-003",
            case_id,
            "192.168.56.12",
            "ipv4",
            "authorized_lab",
            1,
            "Controlled lab",
            expired,
            "2026-11-23T10:00:00Z",
        ),
    )
    db.commit()

    with pytest.raises(ValueError, match="expired"):
        create_operation(
            case_id,
            "target-003",
            "authorized_assessment",
            "test-analyst",
            execution_mode="local",
        )


def test_complete_operation(db, case_id, lab_target):
    run_id = create_operation(
        case_id,
        lab_target,
        "authorized_assessment",
        "test-analyst",
        execution_mode="local",
    )

    start_operation(run_id)

    complete_operation(
        run_id,
        "success",
        outcome_summary="Test completed",
    )

    operation = get_operation(run_id)

    assert operation["status"] == "success"
    assert operation["outcome_summary"] == "Test completed"
    assert operation["started_at_utc"] is not None
    assert operation["completed_at_utc"] is not None


def test_reject_completion_before_start(db, case_id, lab_target):
    run_id = create_operation(
        case_id,
        lab_target,
        "authorized_assessment",
        "test-analyst",
        execution_mode="local",
    )

    with pytest.raises(ValueError, match="cannot be completed"):
        complete_operation(run_id, "success")


def test_reject_starting_operation_twice(db, case_id, lab_target):
    run_id = create_operation(
        case_id,
        lab_target,
        "authorized_assessment",
        "test-analyst",
        execution_mode="local",
    )

    start_operation(run_id)

    with pytest.raises(ValueError, match="cannot be started"):
        start_operation(run_id)


def test_list_operations(db, case_id, lab_target):
    first = create_operation(
        case_id,
        lab_target,
        "authorized_assessment",
        "test-analyst",
        execution_mode="local",
    )

    second = create_operation(
        case_id,
        lab_target,
        "authorized_assessment",
        "test-analyst",
        execution_mode="local",
    )

    operations = list_operations(case_id)

    assert len(operations) == 2
    assert {item["run_id"] for item in operations} == {
        first,
        second,
    }


def test_case_evidence_import_has_no_target(db, case_id):
    run_id = create_operation(
        case_id,
        None,
        "case_evidence_import",
        "test-analyst",
    )

    operation = get_operation(run_id)

    assert operation["target_id"] is None
    assert operation["execution_mode"] is None


def test_reject_case_import_with_target(db, case_id, lab_target):
    with pytest.raises(ValueError, match="must not specify a target"):
        create_operation(
            case_id,
            lab_target,
            "case_evidence_import",
            "test-analyst",
        )


def test_reject_assessment_without_execution_mode(
    db, case_id, lab_target
):
    with pytest.raises(ValueError, match="execution_mode is required"):
        create_operation(
            case_id,
            lab_target,
            "authorized_assessment",
            "test-analyst",
        )
