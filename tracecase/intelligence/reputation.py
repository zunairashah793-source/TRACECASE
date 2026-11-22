import ipaddress
import json
import os
from datetime import datetime, timezone

import requests

from ..contracts import (
    Confidence,
    FindingCategory,
    FindingPayload,
    FindingStatus,
    IndicatorType,
)


SOURCE = "abuseipdb"
API_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = (3.05, 10)
MAX_RESPONSE_BYTES = 1_048_576
RESPONSE_CHUNK_SIZE = 65_536
DEFAULT_MAX_AGE_DAYS = 90


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_public_ip(indicator: str) -> str:
    if not isinstance(indicator, str) or not indicator.strip():
        raise ValueError("A valid IP address is required.")

    try:
        address = ipaddress.ip_address(indicator.strip())
    except ValueError:
        raise ValueError("Invalid IP address.") from None

    checked_address = address
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        checked_address = address.ipv4_mapped

    if (
        not checked_address.is_global
        or checked_address.is_private
        or checked_address.is_loopback
        or checked_address.is_link_local
        or checked_address.is_reserved
        or checked_address.is_multicast
        or checked_address.is_unspecified
    ):
        raise ValueError(
            "Only globally routable unicast IP addresses are allowed."
        )

    return str(address)


def _request_abuseipdb(ip_address: str, api_key: str) -> dict:
    """Request a bounded AbuseIPDB IP reputation response."""

    response = requests.get(
        API_URL,
        headers={
            "Accept": "application/json",
            "Key": api_key,
        },
        params={
            "ipAddress": ip_address,
            "maxAgeInDays": DEFAULT_MAX_AGE_DAYS,
        },
        timeout=TIMEOUT,
        allow_redirects=False,
        stream=True,
    )

    try:
        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int) and 300 <= status_code < 400:
            raise ValueError("AbuseIPDB attempted an HTTP redirect.")

        response.raise_for_status()

        headers = getattr(response, "headers", {})
        if hasattr(headers, "get"):
            content_length = headers.get("Content-Length")
            if content_length is not None:
                try:
                    if int(content_length) > MAX_RESPONSE_BYTES:
                        raise ValueError("AbuseIPDB response exceeded the size limit.")
                except (TypeError, ValueError) as exc:
                    if isinstance(exc, ValueError) and str(exc).startswith("AbuseIPDB"):
                        raise

        if isinstance(response, requests.Response):
            body = bytearray()

            for chunk in response.iter_content(
                chunk_size=RESPONSE_CHUNK_SIZE
            ):
                if not chunk:
                    continue

                body.extend(chunk)

                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError(
                        "AbuseIPDB response exceeded the size limit."
                    )

            try:
                payload = json.loads(
                    body.decode(response.encoding or "utf-8")
                )
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ValueError(
                    "AbuseIPDB returned invalid JSON."
                ) from None
        else:
            payload = response.json()

        if not isinstance(payload, dict):
            raise ValueError("AbuseIPDB returned an unexpected response.")

        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("AbuseIPDB response did not contain valid data.")

        return data

    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


def _non_negative_integer(value):
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _safe_string(value):
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _parse_reputation(data: dict, expected_ip: str) -> dict:
    """Extract only the reputation fields needed by TRACECASE."""

    returned_ip = _safe_string(data.get("ipAddress"))

    if returned_ip is None:
        raise ValueError("AbuseIPDB did not return an IP address.")

    try:
        normalized_returned_ip = _normalize_public_ip(returned_ip)
    except ValueError:
        raise ValueError("AbuseIPDB returned an invalid IP address.") from None

    if normalized_returned_ip != expected_ip:
        raise ValueError("AbuseIPDB returned a different IP address.")

    score = data.get("abuseConfidenceScore")

    if (
        not isinstance(score, int)
        or isinstance(score, bool)
        or not 0 <= score <= 100
    ):
        raise ValueError("AbuseIPDB returned an invalid confidence score.")

    return {
        "ip_address": expected_ip,
        "abuse_confidence_score": score,
        "total_reports": _non_negative_integer(data.get("totalReports")),
        "distinct_reporters": _non_negative_integer(
            data.get("numDistinctUsers")
        ),
        "last_reported_at": _safe_string(data.get("lastReportedAt")),
        "country_code": _safe_string(data.get("countryCode")),
        "usage_type": _safe_string(data.get("usageType")),
        "isp": _safe_string(data.get("isp")),
        "domain": _safe_string(data.get("domain")),
        "is_whitelisted": (
            data.get("isWhitelisted")
            if isinstance(data.get("isWhitelisted"), bool)
            else None
        ),
        "reporting_period_days": DEFAULT_MAX_AGE_DAYS,
    }


def _make_payload(
    *,
    indicator: str,
    indicator_type: IndicatorType,
    status: FindingStatus,
    summary: str,
    finding: dict,
    limitations: list[str],
) -> FindingPayload:
    return FindingPayload(
        indicator=indicator,
        indicator_type=indicator_type,
        category=FindingCategory.EXTERNAL_INTELLIGENCE,
        source=SOURCE,
        collected_at_utc=_utc_now(),
        status=status,
        summary=summary,
        finding=finding,
        confidence=(
            Confidence.MEDIUM
            if status == FindingStatus.SUCCESS
            else Confidence.UNKNOWN
        ),
        limitations=limitations,
        source_url=API_URL,
    )


def collect_reputation(
    *,
    indicator: str,
    indicator_type: str,
) -> list[FindingPayload]:
    """Collect optional AbuseIPDB reputation intelligence for a public IP."""

    normalized_ip = _normalize_public_ip(indicator)

    address = ipaddress.ip_address(normalized_ip)
    expected_type = (
        IndicatorType.IPV4
        if address.version == 4
        else IndicatorType.IPV6
    )

    supplied_type = (
        indicator_type.value
        if isinstance(indicator_type, IndicatorType)
        else str(indicator_type).strip().lower()
    )

    if supplied_type != expected_type.value:
        raise ValueError("Indicator type does not match the supplied IP.")

    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()

    if not api_key:
        return [
            _make_payload(
                indicator=normalized_ip,
                indicator_type=expected_type,
                status=FindingStatus.UNAVAILABLE,
                summary="AbuseIPDB reputation collection is not configured.",
                finding={},
                limitations=[
                    "ABUSEIPDB_API_KEY is not configured.",
                    "No reputation conclusion can be drawn.",
                ],
            )
        ]

    try:
        raw_data = _request_abuseipdb(normalized_ip, api_key)
        finding = _parse_reputation(raw_data, normalized_ip)

        return [
            _make_payload(
                indicator=normalized_ip,
                indicator_type=expected_type,
                status=FindingStatus.SUCCESS,
                summary=(
                    "AbuseIPDB reputation data collected successfully. "
                    f"Abuse confidence score: "
                    f"{finding['abuse_confidence_score']}/100."
                ),
                finding=finding,
                limitations=[
                    "Reputation reflects AbuseIPDB reports within the "
                    f"last {DEFAULT_MAX_AGE_DAYS} days.",
                    "A score of zero does not prove that an IP address "
                    "is benign.",
                    "AbuseIPDB data is one source and should be assessed "
                    "alongside other investigation evidence.",
                ],
            )
        ]

    except requests.RequestException:
        return [
            _make_payload(
                indicator=normalized_ip,
                indicator_type=expected_type,
                status=FindingStatus.UNAVAILABLE,
                summary="AbuseIPDB could not be reached.",
                finding={},
                limitations=[
                    "The AbuseIPDB request failed.",
                    "No reputation conclusion can be drawn.",
                ],
            )
        ]

    except ValueError as exc:
        return [
            _make_payload(
                indicator=normalized_ip,
                indicator_type=expected_type,
                status=FindingStatus.ERROR,
                summary="AbuseIPDB returned an invalid response.",
                finding={},
                limitations=[str(exc)],
            )
        ]

    except Exception:
        return [
            _make_payload(
                indicator=normalized_ip,
                indicator_type=expected_type,
                status=FindingStatus.ERROR,
                summary="Unexpected AbuseIPDB collection error.",
                finding={},
                limitations=[
                    "An unexpected error occurred during collection."
                ],
            )
        ]
