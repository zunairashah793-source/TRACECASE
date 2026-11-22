import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from tracecase.assessment.jobs import (
    REQUIRED_JOB_FIELDS,
    parse_job_json,
    validate_job_data,
)


@pytest.fixture
def valid_job():
    current_time = datetime.now(timezone.utc).replace(microsecond=0)

    requested_time = current_time - timedelta(minutes=1)
    expiry_time = current_time + timedelta(hours=1)

    return {
        "job_id": str(uuid.uuid4()),
        "case_id": str(uuid.uuid4()),
        "target_id": str(uuid.uuid4()),
        "run_id": str(uuid.uuid4()),
        "worker_id": "worker-01",
        "execution_mode": "local",
        "operation": "nmap_scan",
        "target_indicator": "192.168.1.10",
        "target_indicator_type": "ipv4",
        "approved_target_addresses": ["192.168.1.10"],
        "allowed_ports": [80, 443],
        "profile_id": "nmap-safe-profile",
        "authorization_reference": "AUTH-LAB-001",
        "requested_at_utc": requested_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at_utc": expiry_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": "unique-test-nonce-001",
    }


# JSON input validation tests

def test_integer_input_is_rejected():
    with pytest.raises(ValueError, match="JSON text"):
        parse_job_json(123)


def test_none_input_is_rejected():
    with pytest.raises(ValueError, match="JSON text"):
        parse_job_json(None)


def test_empty_string_is_rejected():
    with pytest.raises(ValueError, match="Invalid worker job JSON"):
        parse_job_json("")


def test_whitespace_only_input_is_rejected():
    with pytest.raises(ValueError, match="Invalid worker job JSON"):
        parse_job_json("   ")


def test_json_null_is_rejected():
    with pytest.raises(ValueError, match="JSON object"):
        parse_job_json("null")


def test_json_boolean_is_rejected():
    with pytest.raises(ValueError, match="JSON object"):
        parse_job_json("true")


def test_nan_is_rejected():
    with pytest.raises(ValueError, match="Invalid worker job JSON"):
        parse_job_json('{"value": NaN}')


def test_infinity_is_rejected():
    with pytest.raises(ValueError, match="Invalid worker job JSON"):
        parse_job_json('{"value": Infinity}')


def test_duplicate_json_keys_are_rejected():
    raw_json = '{"worker_id":"first","worker_id":"second"}'

    with pytest.raises(ValueError, match="Invalid worker job JSON"):
        parse_job_json(raw_json)


def test_invalid_json_is_rejected():
    with pytest.raises(ValueError, match="Invalid worker job JSON"):
        parse_job_json('{"job_id":')


def test_non_object_json_is_rejected():
    with pytest.raises(ValueError, match="Worker job must be a JSON object"):
        parse_job_json("[]")


# Basic job validation tests

def test_valid_job_is_accepted(valid_job):
    assert validate_job_data(valid_job) is True


def test_valid_json_is_parsed(valid_job):
    raw_json = json.dumps(valid_job)

    result = parse_job_json(raw_json)

    assert result == valid_job


def test_missing_required_field_is_rejected(valid_job):
    valid_job.pop("worker_id")

    with pytest.raises(ValueError, match="Missing required"):
        validate_job_data(valid_job)


def test_unexpected_field_is_rejected(valid_job):
    valid_job["command"] = "unexpected"

    with pytest.raises(ValueError, match="Unexpected"):
        validate_job_data(valid_job)


def test_invalid_uuid_is_rejected(valid_job):
    valid_job["job_id"] = "not-a-uuid"

    with pytest.raises(ValueError, match="UUID"):
        validate_job_data(valid_job)


def test_unsupported_operation_is_rejected(valid_job):
    valid_job["operation"] = "arbitrary_command"

    with pytest.raises(ValueError, match="operation"):
        validate_job_data(valid_job)


# Approved target address tests

def test_invalid_target_ip_is_rejected(valid_job):
    valid_job["approved_target_addresses"] = ["192.168.1.999"]

    with pytest.raises(ValueError, match="IP"):
        validate_job_data(valid_job)


def test_cidr_range_is_rejected(valid_job):
    valid_job["approved_target_addresses"] = ["192.168.1.0/24"]

    with pytest.raises(ValueError, match="IP"):
        validate_job_data(valid_job)


# Port validation tests

def test_invalid_port_is_rejected(valid_job):
    valid_job["allowed_ports"] = [80, 70000]

    with pytest.raises(ValueError, match="port"):
        validate_job_data(valid_job)


def test_boolean_port_is_rejected(valid_job):
    valid_job["allowed_ports"] = [True]

    with pytest.raises(ValueError, match="port"):
        validate_job_data(valid_job)


# Timestamp validation tests

def test_expiry_before_request_is_rejected(valid_job):
    requested_time = datetime.strptime(
        valid_job["requested_at_utc"],
        "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)

    earlier_expiry = requested_time - timedelta(minutes=1)

    valid_job["expires_at_utc"] = earlier_expiry.strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    with pytest.raises(ValueError, match="expiry"):
        validate_job_data(valid_job)


def test_unexpired_job_is_accepted(valid_job):
    assert validate_job_data(
        valid_job,
        now=datetime.now(timezone.utc)
    ) is True


def test_expired_job_is_rejected(valid_job):
    expiry_time = datetime.strptime(
        valid_job["expires_at_utc"],
        "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)

    with pytest.raises(ValueError, match="expired"):
        validate_job_data(valid_job, now=expiry_time)


# Target indicator validation tests

def test_ipv4_indicator_matches_type(valid_job):
    valid_job["target_indicator"] = "192.168.1.10"
    valid_job["target_indicator_type"] = "ipv4"

    assert validate_job_data(valid_job) is True


def test_ipv4_rejects_ipv6_indicator(valid_job):
    valid_job["target_indicator"] = "2001:db8::1"
    valid_job["target_indicator_type"] = "ipv4"

    with pytest.raises(ValueError):
        validate_job_data(valid_job)


def test_domain_is_normalized_to_lowercase(valid_job):
    valid_job["target_indicator"] = "EXAMPLE.COM"
    valid_job["target_indicator_type"] = "domain"

    validate_job_data(valid_job)

    assert valid_job["target_indicator"] == "example.com"


def test_url_rejects_ftp_scheme(valid_job):
    valid_job["target_indicator"] = "ftp://example.com"
    valid_job["target_indicator_type"] = "url"

    with pytest.raises(ValueError):
        validate_job_data(valid_job)


def test_tls_fingerprint_accepts_sha256(valid_job):
    valid_job["target_indicator"] = "a" * 64
    valid_job["target_indicator_type"] = "tls_certificate"

    assert validate_job_data(valid_job) is True


def test_tls_fingerprint_rejects_invalid_length(valid_job):
    valid_job["target_indicator"] = "a" * 63
    valid_job["target_indicator_type"] = "tls_certificate"

    with pytest.raises(ValueError):
        validate_job_data(valid_job)


# Contract definition test

def test_required_field_definition_contains_sixteen_fields():
    assert len(REQUIRED_JOB_FIELDS) == 16
