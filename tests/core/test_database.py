
import sqlite3

import pytest

from tracecase.core.database import initialize_database, get_connection


EXPECTED_TABLES = {
    "cases",
    "targets",
    "investigation_runs",
    "findings",
    "evidence",
    "case_events",
}


@pytest.fixture
def db(tmp_path, monkeypatch):
    import tracecase.core.database as database

    test_db = tmp_path / "test_tracecase.sqlite3"
    test_instance = tmp_path / "instance"

    monkeypatch.setattr(database, "DATABASE_PATH", test_db)
    monkeypatch.setattr(database, "INSTANCE_DIR", test_instance)

    initialize_database()

    connection = get_connection()

    yield connection

    connection.close()


def test_database_creates_six_tables(db):
    rows = db.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()

    actual = {row["name"] for row in rows}

    assert actual == EXPECTED_TABLES


def test_foreign_keys_enabled(db):
    result = db.execute(
        "PRAGMA foreign_keys"
    ).fetchone()[0]

    assert result == 1


def test_database_integrity(db):
    result = db.execute(
        "PRAGMA integrity_check"
    ).fetchone()[0]

    assert result == "ok"


def test_foreign_key_check_has_no_violations(db):
    result = db.execute(
        "PRAGMA foreign_key_check"
    ).fetchall()

    assert result == []


def test_schema_has_required_tables(db):
    for table in EXPECTED_TABLES:
        result = db.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name=?",
            (table,),
        ).fetchone()

        assert result is not None


def test_reinitialization_does_not_delete_tables(db):
    initialize_database()

    rows = db.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()

    assert {row["name"] for row in rows} == EXPECTED_TABLES
