
import json
import ipaddress
import re
import uuid

from datetime import datetime, timezone
from urllib.parse import urlparse

from tracecase.contracts import (
    IndicatorType,
    TargetKind,
    CaseStatus,
    OperationType,
    ExecutionMode,
    OperationStatus,
    FindingCategory,
    FindingStatus,
    Confidence,
    EvidenceIntegrityStatus,
    ArtifactType,
)


def generate_id():
    return str(uuid.uuid4())


def utc_now():
    return datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def validate_utc_timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Timestamp must be a string")

    try:
        parsed = datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ"
        )
    except ValueError:
        raise ValueError("Invalid UTC timestamp")

    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError("Non-canonical UTC timestamp")

    return value


def validate_uuid(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Invalid UUID")


def validate_required_text(value, field, max_length=500):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")

    value = value.strip()

    if len(value) > max_length:
        raise ValueError(f"{field} exceeds maximum length")

    return value


def validate_json_object(value):
    if isinstance(value, str):
        value = json.loads(value)

    if not isinstance(value, dict):
        raise ValueError("Expected JSON object")

    json.dumps(value)
    return value


def validate_indicator(indicator, indicator_type):
    try:
        indicator_type = IndicatorType(indicator_type)
    except ValueError:
        raise ValueError("Unsupported indicator type")

    indicator = validate_required_text(
        indicator, "indicator", 2048
    )

    if indicator_type in (
        IndicatorType.IPV4,
        IndicatorType.IPV6,
    ):
        address = ipaddress.ip_address(indicator)
        if address.version != (
            4 if indicator_type == IndicatorType.IPV4 else 6
        ):
            raise ValueError("IP version mismatch")
        return str(address)

    if indicator_type == IndicatorType.URL:
        parsed = urlparse(indicator)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs allowed")

        if not parsed.hostname:
            raise ValueError("URL hostname is required")

        return indicator

    if indicator_type == IndicatorType.TLS_CERTIFICATE:
        fingerprint = indicator.lower().replace(":", "")
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("Invalid SHA-256 fingerprint")
        return fingerprint

    if indicator_type in (
        IndicatorType.DOMAIN,
        IndicatorType.SUBDOMAIN,
        IndicatorType.HOSTNAME,
    ):
        normalized = indicator.rstrip(".").encode(
            "idna"
        ).decode("ascii").lower()

        if len(normalized) > 253:
            raise ValueError("Domain is too long")

        labels = normalized.split(".")

        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label,
            )
            for label in labels
        ):
            raise ValueError("Invalid domain name")

        return normalized

    raise ValueError("Unsupported indicator")


def validate_enum(value, enum_class):
    try:
        return enum_class(value).value
    except ValueError:
        raise ValueError(
            f"Invalid {enum_class.__name__}: {value}"
        )
