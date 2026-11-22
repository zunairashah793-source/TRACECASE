
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit


REQUIRED_JOB_FIELDS = frozenset({
    "job_id",
    "case_id",
    "target_id",
    "run_id",
    "worker_id",
    "execution_mode",
    "operation",
    "target_indicator",
    "target_indicator_type",
    "approved_target_addresses",
    "allowed_ports",
    "profile_id",
    "authorization_reference",
    "requested_at_utc",
    "expires_at_utc",
    "nonce",
})

# Public set of accepted AssessmentJob field names.
ALLOWED_JOB_FIELDS = REQUIRED_JOB_FIELDS

SUPPORTED_EXECUTION_MODES = frozenset({
    "local",
    "remote",
})

SUPPORTED_OPERATIONS = frozenset({
    "nmap_scan",
    "pcap_capture",
    "post_access_collect",
})

SUPPORTED_INDICATOR_TYPES = frozenset({
    "ipv4",
    "ipv6",
    "domain",
    "subdomain",
    "url",
    "hostname",
    "tls_certificate",
})

MAX_PORT = 65535


def _normalize_domain(value):
    """Validate and normalize a domain name using IDNA."""

    if not isinstance(value, str) or not value:
        raise ValueError("Invalid domain name.")

    try:
        normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("Invalid domain name.") from error

    if len(normalized) > 253:
        raise ValueError("Invalid domain name.")

    labels = normalized.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label
            )
        ):
            raise ValueError("Invalid domain name.")

    return normalized


def _validate_target_indicator(indicator, indicator_type):
    """Validate and normalize a target indicator."""

    if not isinstance(indicator, str) or not indicator.strip():
        raise ValueError("Invalid target indicator.")

    if indicator_type in {"ipv4", "ipv6"}:
        try:
            address = ipaddress.ip_address(indicator)
        except ValueError as error:
            raise ValueError(
                "Invalid target IP indicator."
            ) from error

        expected_version = 4 if indicator_type == "ipv4" else 6

        if address.version != expected_version:
            raise ValueError(
                "Target indicator does not match its IP type."
            )

        if str(address) != indicator:
            raise ValueError(
                "Target IP indicator must be normalized."
            )

        return str(address)

    if indicator_type in {"domain", "subdomain", "hostname"}:
        return _normalize_domain(indicator)

    if indicator_type == "url":
        try:
            parsed = urlsplit(indicator)

            if parsed.scheme.lower() not in {"http", "https"}:
                raise ValueError("Unsupported URL scheme.")

            if not parsed.netloc or not parsed.hostname:
                raise ValueError("URL host is required.")

            if parsed.username is not None or parsed.password is not None:
                raise ValueError("URL credentials are not allowed.")

            port = parsed.port

            if port is not None and not 1 <= port <= MAX_PORT:
                raise ValueError("Invalid URL port.")

            # Validate DNS hostname when it is not an IP address.
            hostname = parsed.hostname

            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                _normalize_domain(hostname)

        except ValueError as error:
            raise ValueError("Invalid target URL.") from error

        return indicator

    if indicator_type == "tls_certificate":
        fingerprint = indicator.lower()

        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError(
                "TLS certificate indicator must be a SHA-256 fingerprint."
            )

        return fingerprint

    raise ValueError("Unsupported target indicator type.")


def _reject_duplicate_keys(pairs):
    """Reject duplicate keys in any JSON object."""

    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON keys are not allowed.")

        result[key] = value

    return result


def _reject_json_constant(value):
    """Reject non-standard JSON constants such as NaN and Infinity."""

    raise ValueError("Invalid JSON constant.")


def validate_uuid(value, field_name):
    """Validate a canonical UUID string."""

    if not isinstance(value, str):
        raise ValueError(
            f"{field_name} must be a UUID string."
        )

    try:
        parsed = uuid.UUID(value)

    except (ValueError, AttributeError) as error:
        raise ValueError(
            f"Invalid UUID in {field_name}."
        ) from error

    if str(parsed) != value:
        raise ValueError(
            f"{field_name} must use canonical UUID format."
        )

    return True


def validate_utc_timestamp(value, field_name):
    """Validate a canonical UTC timestamp."""

    if not isinstance(value, str):
        raise ValueError(
            f"{field_name} must be a string."
        )

    try:
        parsed = datetime.strptime(
            value,
            "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)

    except ValueError as error:
        raise ValueError(
            f"Invalid UTC timestamp in {field_name}."
        ) from error

    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError(
            f"{field_name} must use canonical UTC format."
        )

    return parsed


def validate_job_fields(job):
    """Check required and unexpected AssessmentJob fields."""

    if not isinstance(job, dict):
        raise ValueError(
            "Worker job must be a JSON object."
        )

    received_fields = set(job.keys())

    missing_fields = REQUIRED_JOB_FIELDS - received_fields
    unexpected_fields = received_fields - REQUIRED_JOB_FIELDS

    if missing_fields:
        raise ValueError(
            f"Missing required job fields: {sorted(missing_fields)}"
        )

    if unexpected_fields:
        raise ValueError(
            f"Unexpected job fields: {sorted(unexpected_fields)}"
        )

    return True


def _validate_nonempty_string(value, field_name):
    """Check that a required text field is a non-empty string."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"Invalid {field_name}."
        )

    return True


def validate_job_data(job, *, now=None):
    """Validate all fields of an incoming worker job."""

    validate_job_fields(job)

    # Validate UUID fields.
    for field in ("job_id", "case_id", "target_id", "run_id"):
        validate_uuid(job[field], field)

    # Validate required text fields.
    text_fields = (
        "worker_id",
        "target_indicator",
        "profile_id",
        "authorization_reference",
        "nonce",
    )

    for field in text_fields:
        _validate_nonempty_string(job[field], field)

    # Validate execution mode.
    execution_mode = job["execution_mode"]

    if (
        not isinstance(execution_mode, str)
        or execution_mode not in SUPPORTED_EXECUTION_MODES
    ):
        raise ValueError("Unsupported execution mode.")

    # Validate worker operation.
    operation = job["operation"]

    if (
        not isinstance(operation, str)
        or operation not in SUPPORTED_OPERATIONS
    ):
        raise ValueError("Unsupported worker operation.")

    # Validate target indicator type.
    indicator_type = job["target_indicator_type"]

    if (
        not isinstance(indicator_type, str)
        or indicator_type not in SUPPORTED_INDICATOR_TYPES
    ):
        raise ValueError("Unsupported target indicator type.")

    # Validate and normalize target indicator.
    job["target_indicator"] = _validate_target_indicator(
        job["target_indicator"],
        indicator_type
    )

    # Validate approved target IP addresses.
    addresses = job["approved_target_addresses"]

    if not isinstance(addresses, list) or not addresses:
        raise ValueError(
            "At least one approved target IP is required."
        )

    for address in addresses:
        if not isinstance(address, str):
            raise ValueError(
                "Target IP address must be a string."
            )

        try:
            parsed = ipaddress.ip_address(address)

        except ValueError as error:
            raise ValueError(
                "Invalid exact target IP address."
            ) from error

        if str(parsed) != address:
            raise ValueError(
                "Target IP address must be normalized."
            )

    if len(set(addresses)) != len(addresses):
        raise ValueError(
            "Duplicate target addresses are not allowed."
        )

    # Validate allowed ports.
    ports = job["allowed_ports"]

    if not isinstance(ports, list) or not ports:
        raise ValueError(
            "At least one allowed port is required."
        )

    for port in ports:
        if type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError(
                "Invalid port number."
            )

    if len(set(ports)) != len(ports):
        raise ValueError(
            "Duplicate ports are not allowed."
        )

    # Validate UTC timestamps.
    requested_at = validate_utc_timestamp(
        job["requested_at_utc"],
        "requested_at_utc"
    )

    expires_at = validate_utc_timestamp(
        job["expires_at_utc"],
        "expires_at_utc"
    )

    if expires_at <= requested_at:
        raise ValueError(
            "Job expiry must be after request time."
        )

    # Validate that the job has not expired.
    if now is None:
        now = datetime.now(timezone.utc)

    if not isinstance(now, datetime):
        raise ValueError("Current time must be a datetime.")

    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Current time must be timezone-aware.")

    now = now.astimezone(timezone.utc)

    if expires_at <= now:
        raise ValueError("Worker job has expired.")

    return True


def parse_job_json(raw_json):
    """Parse JSON and validate the complete worker job."""

    if not isinstance(raw_json, str):
        raise ValueError(
            "Worker job input must be JSON text."
        )

    try:
        job = json.loads(
            raw_json,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )

    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError(
            "Invalid worker job JSON."
        ) from error

    validate_job_data(job)

    return job
