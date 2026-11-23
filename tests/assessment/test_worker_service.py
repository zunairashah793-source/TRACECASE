import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from tracecase.assessment.worker_service import (
    MAX_JOB_SIZE,
    accept_job,
)
from tracecase.contracts import OperationStatus


def make_job(**overrides):
    now = datetime.now(timezone.utc)

    job = {
        "job_id": str(uuid.uuid4()),
        "case_id": str(uuid.uuid4()),
        "target_id": str(uuid.uuid4()),
        "run_id": str(uuid.uuid4()),
        "worker_id": "local-lab-worker",
        "execution_mode": "local",
        "operation": "nmap_scan",
        "target_indicator": "192.0.2.10",
        "target_indicator_type": "ipv4",
        "approved_target_addresses": ["192.0.2.10"],
        "allowed_ports": [80],
        "profile_id": "lab-nmap-profile",
        "authorization_reference": "AUTH-TEST-001",
        "requested_at_utc": (
            now - timedelta(minutes=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at_utc": (
            now + timedelta(minutes=30)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": str(uuid.uuid4()),
    }

    job.update(overrides)
    return job


def make_policy_file(tmp_path):
    policy = {
        "worker_id": "local-lab-worker",
        "allowed_controllers": ["approved-controller"],
        "targets": {
            "TARGET_PLACEHOLDER": {
                "addresses": ["192.0.2.10"],
                "ports": [80, 443],
                "operations": {
                    "nmap_scan": ["lab-nmap-profile"],
                    "pcap_capture": ["lab-capture-profile"],
                    "post_access_collect": ["lab-evidence-profile"],
                },
            }
        },
    }

    # The job target ID is generated dynamically.
    policy["targets"] = {
        "target-id": policy["targets"].pop("TARGET_PLACEHOLDER")
    }

    path = tmp_path / "worker-policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def make_matching_job(**overrides):
    overrides.setdefault("target_id", str(uuid.uuid4()))
    return make_job(**overrides)

def write_policy_for_job(tmp_path, job):
    policy = {
        "worker_id": "local-lab-worker",
        "allowed_controllers": ["approved-controller"],
        "targets": {
            job["target_id"]: {
                "addresses": ["192.0.2.10"],
                "ports": [80, 443],
                "operations": {
                    "nmap_scan": ["lab-nmap-profile"],
                },
            }
        },
    }

    path = tmp_path / "worker-policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def submit(tmp_path, job, *, controller="approved-controller"):
    policy_path = write_policy_for_job(tmp_path, job)
    profile_path = write_profiles(tmp_path, make_profiles())

    return accept_job(
        raw_job_json=json.dumps(job),
        policy_path=policy_path,
        profile_path=profile_path,
        state_path=tmp_path / "worker-state.sqlite3",
        authenticated_controller_id=controller,
    )


def test_accepts_valid_job_and_returns_queued_receipt(tmp_path):
    job = make_matching_job()

    accepted_job, receipt = submit(tmp_path, job)

    assert accepted_job["job_id"] == job["job_id"]
    assert receipt.job_id == job["job_id"]
    assert receipt.worker_id == "local-lab-worker"
    assert receipt.status == OperationStatus.QUEUED
    assert receipt.accepted_at_utc


def test_rejects_unauthorized_controller(tmp_path):
    job = make_matching_job()

    with pytest.raises(ValueError, match="Controller"):
        submit(
            tmp_path,
            job,
            controller="unapproved-controller",
        )


def test_rejects_oversized_job(tmp_path):
    job = make_matching_job()
    policy_path = write_policy_for_job(tmp_path, job)

    with pytest.raises(ValueError, match="too large"):
      accept_job(
    raw_job_json=" " * (MAX_JOB_SIZE + 1),
    policy_path=policy_path,
    profile_path=tmp_path / "worker-profiles.json",
    state_path=tmp_path / "worker-state.sqlite3",
    authenticated_controller_id="approved-controller",
)


def test_rejects_invalid_unicode_job_input(tmp_path):
    with pytest.raises(ValueError, match="UTF-8"):
        accept_job(
            raw_job_json="\ud800",
            policy_path=tmp_path / "worker-policy.json",
            profile_path=tmp_path / "worker-profiles.json",
            state_path=tmp_path / "worker-state.sqlite3",
            authenticated_controller_id="approved-controller",
        )


def test_rejects_future_request_timestamp(tmp_path):
    future = datetime.now(timezone.utc) + timedelta(minutes=5)

    job = make_matching_job(
        requested_at_utc=future.strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at_utc=(
            future + timedelta(minutes=30)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    with pytest.raises(ValueError, match="future"):
        submit(tmp_path, job)


def test_rejects_replayed_job_id(tmp_path):
    job = make_matching_job()

    submit(tmp_path, job)

    with pytest.raises(ValueError, match="already been processed"):
        submit(tmp_path, job)


def test_rejects_reused_nonce_with_different_job_id(tmp_path):
    first_job = make_matching_job()
    submit(tmp_path, first_job)

    second_job = make_matching_job(
        nonce=first_job["nonce"],
    )

    with pytest.raises(ValueError, match="already been processed"):
        submit(tmp_path, second_job)


def test_replay_state_persists_after_new_service_call(tmp_path):
    job = make_matching_job()

    submit(tmp_path, job)

    # A second call uses the same persistent SQLite state file.
    with pytest.raises(ValueError, match="already been processed"):
        submit(tmp_path, job)


def make_profiles():
    return {
        "schema_version": 1,
        "profiles": {
            "lab-nmap-profile": {
                "operation": "nmap_scan",
                "executable_path": r"C:\Program Files\Nmap\nmap.exe",
                "timeout_seconds": 120,
                "max_output_bytes": 5242880,
            },
            "lab-capture-profile": {
                "operation": "pcap_capture",
                "dumpcap_path": r"C:\Program Files\Wireshark\dumpcap.exe",
                "tshark_path": r"C:\Program Files\Wireshark\tshark.exe",
                "interface_device": r"\Device\NPF_{TEST-GUID}",
                "capture_filter": "host 192.0.2.10",
                "duration_seconds": 30,
                "max_file_size_bytes": 10485760,
                "max_output_bytes": 5242880,
            },
            "lab-evidence-profile": {
                "operation": "post_access_collect",
                "collector": "windows_local_read_only",
                "timeout_seconds": 60,
                "max_output_bytes": 5242880,
                "evidence_types": [
                    "system_info",
                    "process_list",
                    "service_list",
                    "network_connections",
                ],
            },
        },
    }


def write_profiles(tmp_path, profiles):
    path = tmp_path / "worker-profiles.json"
    path.write_text(json.dumps(profiles), encoding="utf-8")
    return path


def test_rejects_profile_operation_mismatch(tmp_path):
    job = make_matching_job(
        operation="pcap_capture",
        profile_id="lab-nmap-profile",
    )

    policy_path = write_policy_for_job(tmp_path, job)

    # Allow the profile in the policy so the service
    # reaches the local profile-operation validation.
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["targets"][job["target_id"]]["operations"] = {
        "pcap_capture": ["lab-nmap-profile"]
    }
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    profile_path = write_profiles(tmp_path, make_profiles())

    with pytest.raises(ValueError, match="(?i)operation"):
        accept_job(
            raw_job_json=json.dumps(job),
            policy_path=policy_path,
            profile_path=profile_path,
            state_path=tmp_path / "worker-state.sqlite3",
            authenticated_controller_id="approved-controller",
        )

def test_rejects_job_with_missing_profile_id(tmp_path):
    job = make_matching_job(
        profile_id="unknown-profile",
    )

    policy_path = write_policy_for_job(tmp_path, job)

    # Allow the profile in policy so local profile
    # validation can reject the missing profile.
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["targets"][job["target_id"]]["operations"] = {
        "nmap_scan": ["unknown-profile"]
    }
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    profile_path = write_profiles(tmp_path, make_profiles())

    with pytest.raises(ValueError, match="(?i)profile"):
        accept_job(
            raw_job_json=json.dumps(job),
            policy_path=policy_path,
            profile_path=profile_path,
            state_path=tmp_path / "worker-state.sqlite3",
            authenticated_controller_id="approved-controller",
        )


def test_invalid_profile_does_not_reserve_job_or_nonce(tmp_path):
    job = make_matching_job()
    policy_path = write_policy_for_job(tmp_path, job)
    profile_path = write_profiles(tmp_path, make_profiles())
    state_path = tmp_path / "worker-state.sqlite3"

    # Make the local Nmap profile invalid.
    invalid_profiles = make_profiles()
    invalid_profiles["profiles"]["lab-nmap-profile"]["operation"] = (
        "pcap_capture"
    )
    write_profiles(tmp_path, invalid_profiles)

    with pytest.raises(ValueError):
        accept_job(
            raw_job_json=json.dumps(job),
            policy_path=policy_path,
            profile_path=profile_path,
            state_path=state_path,
            authenticated_controller_id="approved-controller",
        )

    # Restore valid profiles and retry the SAME job.
    write_profiles(tmp_path, make_profiles())

    accepted_job, receipt = accept_job(
        raw_job_json=json.dumps(job),
        policy_path=policy_path,
        profile_path=profile_path,
        state_path=state_path,
        authenticated_controller_id="approved-controller",
    )

    assert accepted_job["job_id"] == job["job_id"]
    assert receipt.job_id == job["job_id"]
    assert receipt.status == OperationStatus.QUEUED



def test_loads_valid_worker_profiles(tmp_path):
    from tracecase.assessment.worker_service import load_worker_profiles

    path = write_profiles(tmp_path, make_profiles())

    result = load_worker_profiles(path)

    assert result["schema_version"] == 1
    assert "lab-nmap-profile" in result["profiles"]
    assert "lab-capture-profile" in result["profiles"]
    assert "lab-evidence-profile" in result["profiles"]


def test_rejects_missing_worker_profile(tmp_path):
    from tracecase.assessment.worker_service import load_worker_profiles

    profiles = make_profiles()
    del profiles["profiles"]["lab-nmap-profile"]

    with pytest.raises(ValueError, match="profile IDs"):
        load_worker_profiles(write_profiles(tmp_path, profiles))


def test_rejects_unsupported_profile_version(tmp_path):
    from tracecase.assessment.worker_service import load_worker_profiles

    profiles = make_profiles()
    profiles["schema_version"] = 2

    with pytest.raises(ValueError, match="schema version"):
        load_worker_profiles(write_profiles(tmp_path, profiles))


def test_rejects_duplicate_profile_json_keys(tmp_path):
    from tracecase.assessment.worker_service import load_worker_profiles

    path = tmp_path / "worker-profiles.json"
    path.write_text(
        '{"schema_version":1,"schema_version":1,"profiles":{}}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate"):
        load_worker_profiles(path)


def test_rejects_invalid_capture_interface(tmp_path):
    from tracecase.assessment.worker_service import load_worker_profiles

    profiles = make_profiles()
    profiles["profiles"]["lab-capture-profile"]["interface_device"] = "Wi-Fi"

    with pytest.raises(ValueError, match="interface"):
        load_worker_profiles(write_profiles(tmp_path, profiles))


def test_rejects_invalid_capture_duration(tmp_path):
    from tracecase.assessment.worker_service import load_worker_profiles

    profiles = make_profiles()
    profiles["profiles"]["lab-capture-profile"]["duration_seconds"] = 999

    with pytest.raises(ValueError, match="duration"):
        load_worker_profiles(write_profiles(tmp_path, profiles))


def test_rejects_invalid_evidence_type(tmp_path):
    from tracecase.assessment.worker_service import load_worker_profiles

    profiles = make_profiles()
    profiles["profiles"]["lab-evidence-profile"]["evidence_types"] = [
        "arbitrary_command"
    ]

    with pytest.raises(ValueError, match="evidence types"):
        load_worker_profiles(write_profiles(tmp_path, profiles))


def test_rejects_non_string_evidence_type(tmp_path):
    from tracecase.assessment.worker_service import load_worker_profiles

    profiles = make_profiles()
    profiles["profiles"]["lab-evidence-profile"]["evidence_types"] = [
        {"unexpected": "object"}
    ]

    with pytest.raises(ValueError, match="evidence types"):
        load_worker_profiles(write_profiles(tmp_path, profiles))



def test_rejects_missing_profile_file(tmp_path):
    from tracecase.assessment.worker_service import load_worker_profiles

    with pytest.raises(ValueError, match="read valid"):
        load_worker_profiles(tmp_path / "missing.json")
