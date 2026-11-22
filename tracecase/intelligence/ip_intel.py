import ipaddress
import json
import math
from datetime import datetime, timezone

import requests

from ..contracts import (
    Confidence,
    FindingCategory,
    FindingPayload,
    FindingStatus,
    IndicatorType,
)

RDAP_BASE_URL = "https://rdap.org/ip/"
RDAP_TIMEOUT = (3.05, 10)
IPWHOIS_BASE_URL = "https://ipwho.is/"
IPWHOIS_TIMEOUT = (3.05, 10)
IP_GEO_BASE_URL = "https://ipapi.co/"
IP_GEO_TIMEOUT = (3.05, 10)

# Bound provider responses so malformed or unexpectedly large payloads cannot
# consume unbounded memory. Real requests responses are streamed below.
MAX_RESPONSE_BYTES = 1_048_576
RESPONSE_CHUNK_SIZE = 65_536


def safe_string(value):
    """Return a cleaned non-empty string, or None."""
    return value.strip() if isinstance(value, str) and value.strip() else None


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
        raise ValueError("Only globally routable unicast IP addresses are allowed.")

    return str(address)


def _request_json(url: str, timeout: tuple[float, int]) -> dict:
    """Request bounded JSON without following provider-controlled redirects."""
    response = requests.get(
        url,
        headers={"Accept": "application/rdap+json, application/json"},
        timeout=timeout,
        allow_redirects=False,
        stream=True,
    )
    try:
        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int) and 300 <= status_code < 400:
            raise ValueError("Provider attempted an HTTP redirect.")

        response.raise_for_status()

        headers = getattr(response, "headers", {})
        if hasattr(headers, "get"):
            content_length = headers.get("Content-Length")
            if content_length is not None:
                try:
                    if int(content_length) > MAX_RESPONSE_BYTES:
                        raise ValueError("Provider response exceeded the size limit.")
                except (TypeError, ValueError) as exc:
                    if isinstance(exc, ValueError) and str(exc).startswith("Provider"):
                        raise
                    # Ignore a malformed Content-Length; the streamed byte cap
                    # remains authoritative.

        # requests.Response is streamed in production. Lightweight test doubles
        # continue to use .json(), keeping unit tests simple.
        if isinstance(response, requests.Response):
            body = bytearray()
            for chunk in response.iter_content(chunk_size=RESPONSE_CHUNK_SIZE):
                if not chunk:
                    continue
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("Provider response exceeded the size limit.")
            try:
                payload = json.loads(body.decode(response.encoding or "utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ValueError("Provider returned invalid JSON.") from None
        else:
            payload = response.json()

        if not isinstance(payload, dict):
            raise ValueError("Provider returned an unexpected response.")
        return payload
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()


def _fetch_ip_rdap(indicator: str) -> dict:
    """Fetch the RDAP registration record for a public IP address."""
    public_ip = _normalize_public_ip(indicator)
    try:
        return _request_json(
            f"{RDAP_BASE_URL}{public_ip}",
            RDAP_TIMEOUT,
        )
    except ValueError as exc:
        if "invalid JSON" in str(exc) or "unexpected response" in str(exc):
            raise ValueError("RDAP service returned an invalid response.") from None
        raise


def _parse_ip_rdap(record: dict) -> dict:
    """Extract registration metadata without personal contact details."""
    if not isinstance(record, dict):
        raise ValueError("RDAP record must be a dictionary.")

    raw_cidrs = record.get("cidr0_cidrs")
    if not isinstance(raw_cidrs, list):
        raw_cidrs = []
    cidrs = []
    for item in raw_cidrs:
        if not isinstance(item, dict):
            continue
        prefix = item.get("v4prefix") or item.get("v6prefix")
        length = item.get("length")
        if not isinstance(prefix, str) or not isinstance(length, int) or isinstance(length, bool):
            continue
        try:
            network = ipaddress.ip_network(f"{prefix}/{length}", strict=False)
        except ValueError:
            continue
        if (network.version == 4 and not 0 <= length <= 32) or (
            network.version == 6 and not 0 <= length <= 128
        ):
            continue
        cidrs.append({"prefix": str(network.network_address), "length": length})

    raw_events = record.get("events")
    if not isinstance(raw_events, list):
        raw_events = []
    events = []
    for item in raw_events:
        if not isinstance(item, dict):
            continue
        action = safe_string(item.get("eventAction"))
        date = safe_string(item.get("eventDate"))
        if action and date:
            events.append({"action": action, "date": date})

    raw_entities = record.get("entities")
    if not isinstance(raw_entities, list):
        raw_entities = []
    registrants = []
    for entity in raw_entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if not isinstance(roles, list) or "registrant" not in roles:
            continue

        entity_name = None
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
            for field in vcard[1]:
                if (
                    isinstance(field, list)
                    and len(field) >= 4
                    and field[0] == "fn"
                    and isinstance(field[3], str)
                ):
                    entity_name = safe_string(field[3])
                    break

        registrants.append({
            "handle": safe_string(entity.get("handle")),
            "name": entity_name,
        })

    raw_status = record.get("status")
    status = raw_status if isinstance(raw_status, list) else []

    return {
        "name": safe_string(record.get("name")),
        "handle": safe_string(record.get("handle")),
        "allocation_type": safe_string(record.get("type")),
        "country": safe_string(record.get("country")),
        "start_address": safe_string(record.get("startAddress")),
        "end_address": safe_string(record.get("endAddress")),
        "ip_version": safe_string(record.get("ipVersion")),
        "parent_handle": safe_string(record.get("parentHandle")),
        "cidrs": cidrs,
        "status": [value for value in status if isinstance(value, str)],
        "events": events,
        "registrants": registrants,
    }


def _fetch_ip_asn(indicator: str) -> dict:
    """Fetch ASN and ISP information for a public IP address."""
    public_ip = _normalize_public_ip(indicator)
    record = _request_json(
        f"{IPWHOIS_BASE_URL}{public_ip}",
        IPWHOIS_TIMEOUT,
    )
    if record.get("success") is not True:
        raise ValueError("IP intelligence provider could not identify this IP.")

    returned_ip = record.get("ip")
    if not isinstance(returned_ip, str):
        raise ValueError("IP intelligence provider returned no valid IP.")
    if _normalize_public_ip(returned_ip) != public_ip:
        raise ValueError("IP intelligence provider returned a mismatched IP.")
    return record


def _parse_ip_asn(record: dict) -> dict:
    """Extract ASN and ISP metadata from an IPWho.is response."""
    if not isinstance(record, dict):
        raise ValueError("IP intelligence record must be a dictionary.")

    connection = record.get("connection")
    if not isinstance(connection, dict):
        connection = {}

    asn = connection.get("asn")
    if isinstance(asn, bool) or not isinstance(asn, (int, str)):
        asn = None
    elif isinstance(asn, str) and not asn.strip().isdigit():
        asn = None

    return {
        "asn": asn,
        "organisation": safe_string(connection.get("org")),
        "isp": safe_string(connection.get("isp")),
        "domain": safe_string(connection.get("domain")),
    }


def _valid_coordinate(value, minimum: float, maximum: float):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or not minimum <= value <= maximum:
        return None
    return value


def _normalize_geo_record(record: dict, provider: str, source_url: str) -> dict:
    """Convert provider-specific GeoIP fields into a common structure."""
    if provider == "IPWHOIS":
        timezone_data = record.get("timezone")
        timezone_value = (
            timezone_data.get("id") if isinstance(timezone_data, dict)
            else timezone_data
        )
        connection = record.get("connection")
        if not isinstance(connection, dict):
            connection = {}
        normalized = {
            "city": record.get("city"),
            "region": record.get("region"),
            "country_name": record.get("country"),
            "country_code": record.get("country_code"),
            "latitude": record.get("latitude"),
            "longitude": record.get("longitude"),
            "timezone": timezone_value,
            "org": connection.get("org"),
        }
    else:
        normalized = {
            "city": record.get("city"),
            "region": record.get("region"),
            "country_name": record.get("country_name"),
            "country_code": record.get("country_code"),
            "latitude": record.get("latitude"),
            "longitude": record.get("longitude"),
            "timezone": record.get("timezone"),
            "org": record.get("org"),
        }

    normalized["provider"] = provider
    normalized["source_url"] = source_url
    return normalized


def _fetch_ip_geo(indicator: str) -> dict:
    """Fetch approximate GeoIP data from IPWho.is, falling back to ipapi.co."""
    public_ip = _normalize_public_ip(indicator)
    failures = []

    primary_url = f"{IPWHOIS_BASE_URL}{public_ip}"
    try:
        record = _request_json(primary_url, IPWHOIS_TIMEOUT)
        if record.get("success") is not True:
            raise ValueError("IPWho.is could not identify this IP.")
        returned_ip = record.get("ip")
        if (
            not isinstance(returned_ip, str)
            or _normalize_public_ip(returned_ip) != public_ip
        ):
            raise ValueError("IPWho.is returned a mismatched IP.")
        return _normalize_geo_record(record, "IPWHOIS", primary_url)
    except (requests.RequestException, ValueError) as exc:
        failures.append(f"IPWho.is: {_safe_failure_reason(exc)}")

    fallback_url = f"{IP_GEO_BASE_URL}{public_ip}/json/"
    try:
        record = _request_json(fallback_url, IP_GEO_TIMEOUT)
        if record.get("error"):
            raise ValueError("ipapi.co returned a provider error.")
        returned_ip = record.get("ip")
        if (
            not isinstance(returned_ip, str)
            or _normalize_public_ip(returned_ip) != public_ip
        ):
            raise ValueError("ipapi.co returned a mismatched IP.")
        return _normalize_geo_record(record, "IPAPI", fallback_url)
    except (requests.RequestException, ValueError) as exc:
        failures.append(f"ipapi.co: {_safe_failure_reason(exc)}")

    raise ValueError("All GeoIP providers are unavailable. " + "; ".join(failures))


def _parse_ip_geo(record: dict) -> dict:
    """Extract non-sensitive, approximate location information."""
    if not isinstance(record, dict):
        raise ValueError("Invalid GeoIP record.")

    return {
        "city": safe_string(record.get("city")),
        "region": safe_string(record.get("region")),
        "country": safe_string(record.get("country_name")),
        "country_code": safe_string(record.get("country_code")),
        "latitude": _valid_coordinate(record.get("latitude"), -90, 90),
        "longitude": _valid_coordinate(record.get("longitude"), -180, 180),
        "timezone": safe_string(record.get("timezone")),
        "network_organisation": safe_string(record.get("org")),
        "geo_provider": safe_string(record.get("provider")),
        "location_type": "Approximate IP-based location",
    }


def _safe_failure_reason(exc: Exception) -> str:
    """Return a bounded, non-sensitive failure description."""
    if isinstance(exc, requests.Timeout):
        return "provider request timed out"
    if isinstance(exc, requests.HTTPError):
        return "provider returned an HTTP error"
    if isinstance(exc, requests.ConnectionError):
        return "provider connection failed"
    if isinstance(exc, requests.RequestException):
        return "provider request failed"
    if isinstance(exc, ValueError):
        return "provider response was invalid or rejected"
    return "unexpected collection error"


def collect_ip_intel(
    *,
    indicator: str,
    indicator_type: str,
) -> list[FindingPayload]:
    """Collect independent RDAP, ASN/ISP and approximate GeoIP findings."""
    normalized_ip = _normalize_public_ip(indicator)
    expected_type = (
        IndicatorType.IPV4
        if ipaddress.ip_address(normalized_ip).version == 4
        else IndicatorType.IPV6
    )
    supplied_type = (
        indicator_type.value
        if isinstance(indicator_type, IndicatorType)
        else str(indicator_type).strip().lower()
    )
    if supplied_type != expected_type.value:
        raise ValueError("Indicator type does not match the supplied IP.")

    collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    results: list[FindingPayload] = []

    sources = [
        ("rdap", f"{RDAP_BASE_URL}{normalized_ip}", _fetch_ip_rdap, _parse_ip_rdap),
        ("ipwhois", f"{IPWHOIS_BASE_URL}{normalized_ip}", _fetch_ip_asn, _parse_ip_asn),
        ("geoip", None, _fetch_ip_geo, _parse_ip_geo),
    ]

    for source_name, source_url, fetcher, parser in sources:
        try:
            raw_record = fetcher(normalized_ip)
            finding = parser(raw_record)
            actual_source_url = (
                raw_record.get("source_url")
                if source_name == "geoip" and isinstance(raw_record, dict)
                else source_url
            )
            results.append(FindingPayload(
                indicator=normalized_ip,
                indicator_type=expected_type,
                category=FindingCategory.EXTERNAL_INTELLIGENCE,
                source=source_name,
                collected_at_utc=collected_at,
                status=FindingStatus.SUCCESS,
                summary=f"{source_name.upper()} intelligence collected successfully.",
                finding=finding,
                confidence=Confidence.MEDIUM,
                limitations=[],
                source_url=actual_source_url,
            ))
        except Exception as exc:
            results.append(FindingPayload(
                indicator=normalized_ip,
                indicator_type=expected_type,
                category=FindingCategory.EXTERNAL_INTELLIGENCE,
                source=source_name,
                collected_at_utc=collected_at,
                status=FindingStatus.UNAVAILABLE,
                summary=f"{source_name.upper()} intelligence could not be collected.",
                finding={},
                confidence=Confidence.UNKNOWN,
                limitations=[_safe_failure_reason(exc)],
                source_url=source_url,
            ))

    return results
