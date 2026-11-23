
"""Secure admission and replay protection for TRACECASE worker jobs."""

import json
import ntpath
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from tracecase.assessment.jobs import (
    parse_job_json,
    validate_utc_timestamp,
)
from tracecase.contracts import JobReceipt, OperationStatus
from tracecase.network.worker_policy import (
    load_worker_policy,
    validate_job_policy,
)


MAX_JOB_SIZE = 64 * 1024
MAX_PROFILE_FILE_SIZE = 1024 * 1024

PROFILE_IDS = {
    "lab-nmap-profile",
    "lab-capture-profile",
    "lab-evidence-profile",
}


def _utc_now():
    """Return the current UTC time in canonical format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_job_time(job):
    """Reject future-dated and expired jobs."""
    now = datetime.now(timezone.utc)

    requested_at = validate_utc_timestamp(
        job["requested_at_utc"],
        "requested_at_utc",
    )

    expires_at = validate_utc_timestamp(
        job["expires_at_utc"],
        "expires_at_utc",
    )

    if requested_at > now:
        raise ValueError("Job request timestamp is in the future.")

    if expires_at <= now:
        raise ValueError("Worker job has expired.")


def _reserve_job(state_path, job):
    """Persist job ID and nonce to prevent replay after restart."""
    state_path = Path(state_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with sqlite3.connect(state_path, timeout=10) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS processed_jobs (
                    job_id TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL UNIQUE,
                    accepted_at_utc TEXT NOT NULL
                )
            """)

            connection.execute(
                """
                INSERT INTO processed_jobs (
                    job_id,
                    nonce,
                    accepted_at_utc
                )
                VALUES (?, ?, ?)
                """,
                (
                    job["job_id"],
                    job["nonce"],
                    _utc_now(),
                ),
            )

            connection.commit()

    except sqlite3.IntegrityError as error:
        raise ValueError(
            "Job ID or nonce has already been processed."
        ) from error

    except sqlite3.Error as error:
        raise ValueError(
            "Unable to update worker replay-protection state."
        ) from error


def _profile_pairs_no_duplicates(pairs):
    """Reject duplicate keys in profile JSON."""
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate worker profile JSON key.")
        result[key] = value

    return result


def _profile_constant_rejected(value):
    """Reject non-standard JSON constants."""
    raise ValueError(f"Invalid JSON constant: {value}")


def _require_profile_fields(profile, expected_fields):
    """Require an exact set of profile fields."""
    if not isinstance(profile, dict):
        raise ValueError("Worker profile must be a JSON object.")

    if set(profile) != expected_fields:
        raise ValueError(
            "Worker profile has missing or unexpected fields."
        )


def _validate_windows_executable(value, field_name):
    """Validate a fixed absolute Windows executable path."""
    if (
        not isinstance(value, str)
        or not ntpath.isabs(value)
        or "\x00" in value
    ):
        raise ValueError(f"Invalid executable path: {field_name}")


def _validate_profile_limits(profile, timeout_field, output_field):
    """Validate execution timeout and output size limits."""
    timeout = profile[timeout_field]
    output_size = profile[output_field]

    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ValueError("Invalid worker profile timeout.")

    if (
        type(output_size) is not int
        or not 1024 <= output_size <= 100 * 1024 * 1024
    ):
        raise ValueError("Invalid worker profile output limit.")


def load_worker_profiles(profile_path: Path) -> dict:
    """Load and strictly validate host-local worker profiles."""
    profile_path = Path(profile_path)

    try:
        if profile_path.stat().st_size > MAX_PROFILE_FILE_SIZE:
            raise ValueError("Worker profile file is too large.")

        raw_data = profile_path.read_text(encoding="utf-8")

        data = json.loads(
            raw_data,
            object_pairs_hook=_profile_pairs_no_duplicates,
            parse_constant=_profile_constant_rejected,
        )

    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(
            "Unable to read valid worker profile JSON."
        ) from error

    _require_profile_fields(data, {"schema_version", "profiles"})

    if (
        type(data["schema_version"]) is not int
        or data["schema_version"] != 1
    ):
        raise ValueError("Unsupported worker profile schema version.")

    profiles = data["profiles"]

    if not isinstance(profiles, dict) or set(profiles) != PROFILE_IDS:
        raise ValueError(
            "Worker profile IDs do not match the required profiles."
        )

    # Validate Nmap profile.
    nmap = profiles["lab-nmap-profile"]

    _require_profile_fields(
        nmap,
        {
            "operation",
            "executable_path",
            "timeout_seconds",
            "max_output_bytes",
        },
    )

    if nmap["operation"] != "nmap_scan":
        raise ValueError("Invalid Nmap profile operation.")

    _validate_windows_executable(
        nmap["executable_path"],
        "executable_path",
    )
    _validate_profile_limits(
        nmap,
        "timeout_seconds",
        "max_output_bytes",
    )

    # Validate PCAP capture profile.
    capture = profiles["lab-capture-profile"]

    _require_profile_fields(
        capture,
        {
            "operation",
            "dumpcap_path",
            "tshark_path",
            "interface_device",
            "capture_filter",
            "duration_seconds",
            "max_file_size_bytes",
            "max_output_bytes",
        },
    )

    if capture["operation"] != "pcap_capture":
        raise ValueError("Invalid capture profile operation.")

    _validate_windows_executable(
        capture["dumpcap_path"],
        "dumpcap_path",
    )
    _validate_windows_executable(
        capture["tshark_path"],
        "tshark_path",
    )

    if (
        not isinstance(capture["interface_device"], str)
        or not capture["interface_device"].startswith(r"\Device\NPF_")
    ):
        raise ValueError("Invalid preconfigured capture interface.")

    if (
        not isinstance(capture["capture_filter"], str)
        or not capture["capture_filter"].strip()
        or len(capture["capture_filter"]) > 256
    ):
        raise ValueError("Invalid preconfigured capture filter.")

    if (
        type(capture["duration_seconds"]) is not int
        or not 1 <= capture["duration_seconds"] <= 300
    ):
        raise ValueError("Invalid capture duration.")

    if (
        type(capture["max_file_size_bytes"]) is not int
        or not 1024 <= capture["max_file_size_bytes"]
        <= 100 * 1024 * 1024
    ):
        raise ValueError("Invalid capture file size limit.")

    _validate_profile_limits(
        capture,
        "duration_seconds",
        "max_output_bytes",
    )

    # Validate fixed read-only evidence profile.
    evidence = profiles["lab-evidence-profile"]

    _require_profile_fields(
        evidence,
        {
            "operation",
            "collector",
            "timeout_seconds",
            "max_output_bytes",
            "evidence_types",
        },
    )

    if (
        evidence["operation"] != "post_access_collect"
        or evidence["collector"] != "windows_local_read_only"
    ):
        raise ValueError("Invalid read-only evidence profile.")

    _validate_profile_limits(
        evidence,
        "timeout_seconds",
        "max_output_bytes",
    )

    allowed_evidence = {
        "system_info",
        "process_list",
        "service_list",
        "network_connections",
        "system_log",
        "test_file",
    }

    evidence_types = evidence["evidence_types"]

    if (
        not isinstance(evidence_types, list)
        or not evidence_types
        or any(
            not isinstance(item, str) or item not in allowed_evidence
            for item in evidence_types
        )
        or len(evidence_types) != len(set(evidence_types))
    ):
        raise ValueError("Invalid read-only evidence types.")


    return data


def accept_job(
    *,
    raw_job_json: str,
    policy_path: Path,
    profile_path: Path,
    state_path: Path,
    authenticated_controller_id: str,
) -> tuple[dict, JobReceipt]:
    """
    Validate and accept one job from an authenticated controller.

    authenticated_controller_id must come from the trusted transport
    layer, never from the submitted job.
    """
    if not isinstance(raw_job_json, str):
        raise ValueError("Worker job input must be JSON text.")

    try:
        job_size = len(raw_job_json.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise ValueError(
            "Worker job must contain valid UTF-8 text."
        ) from error

    if job_size > MAX_JOB_SIZE:
        raise ValueError("Worker job is too large.")


    # Strict JSON parsing and existing job validation.
    job = parse_job_json(raw_job_json)

    # Reject future request timestamps and expired jobs.
    _check_job_time(job)

    # Load independent host-local worker policy.
    policy = load_worker_policy(policy_path)

    # Validate authenticated controller and local permissions.
    validate_job_policy(
        job=job,
        policy=policy,
        authenticated_controller_id=authenticated_controller_id,
    )

    # Load and validate host-local execution profiles.
    profiles = load_worker_profiles(profile_path)

    selected_profile = profiles["profiles"].get(job["profile_id"])

    if selected_profile is None:
        raise ValueError("Requested worker profile is not configured.")

    if selected_profile["operation"] != job["operation"]:
        raise ValueError(
            "Worker profile operation does not match the job."
        )

    # Persist job ID and nonce before acceptance.
    _reserve_job(state_path, job)

    receipt = JobReceipt(
        job_id=job["job_id"],
        worker_id=policy["worker_id"],
        accepted_at_utc=_utc_now(),
        status=OperationStatus.QUEUED,
    )

    return job, receipt
