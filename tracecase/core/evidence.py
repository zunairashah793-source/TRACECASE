
import json

from tracecase.core.database import get_connection
from tracecase.core.validators import generate_id, utc_now, validate_required_text


def create_evidence(data: dict) -> dict:
    evidence_reference = generate_id()
    created_at = utc_now()

    required_fields = [
        "case_id",
        "run_id",
        "evidence_type",
        "original_filename",
        "stored_relative_path",
        "size_bytes",
        "sha256",
        "source_tool",
    ]

    for field in required_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO evidence (
                evidence_reference,
                case_id,
                target_id,
                run_id,
                evidence_type,
                original_filename,
                stored_relative_path,
                mime_type,
                size_bytes,
                sha256,
                source_tool,
                collected_at_utc,
                received_at_utc,
                integrity_status,
                notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_reference,
                data["case_id"],
                data.get("target_id"),
                data["run_id"],
                data["evidence_type"],
                data["original_filename"],
                data["stored_relative_path"],
                data.get("mime_type"),
                data["size_bytes"],
                data["sha256"],
                data["source_tool"],
                data.get("collected_at_utc"),
                created_at,
                data.get("integrity_status", "not_verified"),
                data.get("notes"),
            ),
        )

        connection.commit()

        return get_evidence(evidence_reference)

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_evidence(evidence_reference: str) -> dict | None:
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM evidence
            WHERE evidence_reference = ?
            """,
            (evidence_reference,),
        ).fetchone()

        return dict(row) if row else None

    finally:
        connection.close()


def list_evidence(case_id: str) -> list[dict]:
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM evidence
            WHERE case_id = ?
            ORDER BY received_at_utc DESC
            """,
            (case_id,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
