
import sqlite3
from pathlib import Path

# Project root: TRACECASE/
PROJECT_ROOT = Path(__file__).resolve().parents[2]

INSTANCE_DIR = PROJECT_ROOT / "instance"
DATABASE_PATH = INSTANCE_DIR / "tracecase.sqlite3"
SCHEMA_PATH = Path(__file__).with_name("schema.sql")

BUSY_TIMEOUT_MS = 5000


def get_connection() -> sqlite3.Connection:
    """Create a configured SQLite database connection."""

    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        str(DATABASE_PATH),
        timeout=BUSY_TIMEOUT_MS / 1000,
    )

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(
        f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}"
    )

    return connection


def initialize_database() -> None:
    """Create the database tables without deleting existing data."""

    if not SCHEMA_PATH.is_file():
        raise FileNotFoundError(
            f"Database schema not found: {SCHEMA_PATH}"
        )

    schema = SCHEMA_PATH.read_text(encoding="utf-8")

    connection = get_connection()

    try:
        connection.executescript(schema)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
