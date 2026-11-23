
import pytest

from tracecase.core.database import (
    get_connection,
    initialize_database,
)
from tracecase.reports.data import get_case_report_data


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Create an isolated temporary database for each test."""

    import tracecase.core.database as database

    instance_dir = tmp_path / "instance"
    database_path = instance_dir / "tracecase.sqlite3"

    monkeypatch.setattr(database, "INSTANCE_DIR", instance_dir)
    monkeypatch.setattr(database, "DATABASE_PATH", database_path)

    initialize_database()

    connection = get_connection()

    yield connection

    connection.close()


@pytest.fixture
def sample_case(db):
    """Insert a sample investigation case."""

    db.execute(
        """
        INSERT INTO cases (
            case_id,
            title,
            description,
            scope_description,
            status,
            created_at_utc,
            updated_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "case-001",
            "Test Investigation",
            "Test case description",
            "Authorized private lab investigation",
            "open",
            "2026-11-23T10:00:00Z",
            "2026-11-23T10:00:00Z",
        ),
    )

    db.commit()
    return "case-001"


def test_report_returns_case_information(db, sample_case):
    report = get_case_report_data(sample_case)

    assert report["case"]["case_id"] == sample_case
    assert report["case"]["title"] == "Test Investigation"
    assert report["case"]["status"] == "open"


def test_report_contains_all_eleven_sections(db, sample_case):
    report = get_case_report_data(sample_case)

    assert set(report.keys()) == {
        "generated_at_utc",
        "case",
        "scope",
        "targets",
        "investigation_runs",
        "findings",
        "evidence",
        "timeline_events",
        "limitations",
        "source_attribution",
        "summary_counts",
    }

    assert report["generated_at_utc"].endswith("Z")


def test_empty_case_returns_empty_collections(db, sample_case):
    report = get_case_report_data(sample_case)

    assert report["targets"] == []
    assert report["investigation_runs"] == []
    assert report["findings"] == []
    assert report["evidence"] == []
    assert report["timeline_events"] == []
    assert report["limitations"] == []
    assert report["source_attribution"] == []

    assert report["summary_counts"] == {
        "targets": 0,
        "investigation_runs": 0,
        "findings": 0,
        "evidence": 0,
        "timeline_events": 0,
    }


def test_missing_case_raises_error(db):
    with pytest.raises(ValueError, match="Case not found"):
        get_case_report_data("missing-case")


def test_report_does_not_mix_cases(db, sample_case):
    """Records belonging to another case must not appear in this report."""

    db.execute(
        """
        INSERT INTO cases (
            case_id,
            title,
            description,
            scope_description,
            status,
            created_at_utc,
            updated_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "case-002",
            "Second Investigation",
            "Another test case",
            "Separate authorized lab",
            "open",
            "2026-11-23T11:00:00Z",
            "2026-11-23T11:00:00Z",
        ),
    )

    db.execute(
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
            notes,
            created_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "target-002",
            "case-002",
            "192.168.56.102",
            "ipv4",
            "authorized_lab",
            "Test VM",
            1,
            "Private lab network",
            "Authorized demonstration",
            "",
            "2026-11-23T11:00:00Z",
        ),
    )

    db.commit()

    report = get_case_report_data(sample_case)

    assert report["case"]["case_id"] == "case-001"
    assert report["targets"] == []
    assert report["summary_counts"]["targets"] == 0
