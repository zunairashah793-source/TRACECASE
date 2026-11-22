
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


MAX_FILE_SIZE = 5 * 1024 * 1024

SUPPORTED_SUFFIXES = {
    ".json",
    ".csv",
    ".txt",
    ".log",
}


def parse_lab_evidence_file(artifact_path: Path) -> dict:
    """Read and extract text from a saved lab evidence file."""

    artifact_path = Path(artifact_path)

    if not artifact_path.is_file():
        raise ValueError("Evidence file does not exist.")

    if artifact_path.suffix.lower() not in SUPPORTED_SUFFIXES:
        raise ValueError("Unsupported evidence file format.")

    if artifact_path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError("Evidence file exceeds the allowed size.")

    try:
        content = artifact_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError as error:
        raise ValueError("Unable to read evidence file.") from error

    suffix = artifact_path.suffix.lower()

    try:
        if suffix == ".json":
            extracted_data = json.loads(content)

        elif suffix == ".csv":
            rows = list(csv.DictReader(content.splitlines()))
            extracted_data = rows

        else:
            extracted_data = content.splitlines()

    except (json.JSONDecodeError, csv.Error) as error:
        raise ValueError("Invalid evidence file content.") from error

    return {
        "file_name": artifact_path.name,
        "file_type": suffix,
        "data": extracted_data,
    }


def analyze_lab_evidence(
    *,
    artifact_path: Path,
    artifact_type: str,
    indicator: str,
    indicator_type: str,
    source_tool: str
) -> list[dict]:
    """Convert lab evidence into a FindingPayload-compatible list."""

    if not isinstance(indicator, str) or not indicator.strip():
        raise ValueError("indicator must be a non-empty string")

    if not isinstance(indicator_type, str) or not indicator_type.strip():
        raise ValueError("indicator_type must be a non-empty string")

    if not isinstance(artifact_type, str) or not artifact_type.strip():
        raise ValueError("artifact_type must be a non-empty string")

    if not isinstance(source_tool, str) or not source_tool.strip():
        raise ValueError("source_tool must be a non-empty string")

    evidence = parse_lab_evidence_file(artifact_path)

    collected_at_utc = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    payload = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "category": "post_access_evidence",
        "source": source_tool.strip().lower(),
        "collected_at_utc": collected_at_utc,
        "status": "success",
        "summary": (
            f"Lab evidence parsed successfully: "
            f"{evidence['file_name']}."
        ),
        "finding": {
            "artifact_type": artifact_type,
            "file_name": evidence["file_name"],
            "file_type": evidence["file_type"],
            "data": evidence["data"],
        },
        "confidence": "medium",
        "limitations": [
            "Results contain only information present in the supplied evidence file.",
            "The parser does not independently verify the accuracy of the evidence."
        ],
        "source_url": None,
    }

    return [payload]
