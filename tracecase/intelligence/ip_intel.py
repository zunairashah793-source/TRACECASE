
import ipaddress
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

    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
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


def _fetch_ip_rdap(indicator: str) -> dict:
    """Fetch the RDAP registration record for a public IP address."""
    public_ip = _normalize_public_ip(indicator)

    response = requests.get(
        f"{RDAP_BASE_URL}{public_ip}",
        headers={"Accept": "application/rdap+json, application/json"},
        timeout=RDAP_TIMEOUT,
        allow_redirects=True,
    )
    response.raise_for_status()

    try:
        record = response.json()
    except ValueError:
        raise ValueError("RDAP service returned invalid JSON.") from None

    if not isinstance(record, dict):
        raise ValueError("RDAP service returned an unexpected response.")

    return record


def _parse_ip_rdap(record: dict) -> dict:
    """Extract registration metadata without personal contact details."""
    if not isinstance(record, dict):
        raise ValueError("RDAP record must be a dictionary.")

    cidrs = []

    for item in record.get("cidr0_cidrs", []):
        if not isinstance(item, dict):
            continue

        prefix = item.get("v4prefix") or item.get("v6prefix")
        length = item.get("length")

        if isinstance(prefix, str) and isinstance(length, int):
            cidrs.append({
                "prefix": prefix,
                "length": length,
            })

    events = []

    for item in record.get("events", []):
        if not isinstance(item, dict):
            continue

        action = item.get("eventAction")
        date = item.get("eventDate")

        if isinstance(action, str) and isinstance(date, str):
            events.append({
                "action": action,
                "date": date,
            })

    registrants = []

    for entity in record.get("entities", []):
        if not isinstance(entity, dict):
            continue

        roles = entity.get("roles", [])

        if not isinstance(roles, list) or "registrant" not in roles:
            continue

        entity_name = None
        vcard = entity.get("vcardArray")

        if (
            isinstance(vcard, list)
            and len(vcard) >= 2
            and isinstance(vcard[1], list)
        ):
            for field in vcard[1]:
                if (
                    isinstance(field, list)
                    and len(field) >= 4
                    and field[0] == "fn"
                    and isinstance(field[3], str)
                ):
                    entity_name = field[3]
                    break

        registrants.append({
            "handle": entity.get("handle"),
            "name": entity_name,
        })

    return {
        "name": record.get("name"),
        "handle": record.get("handle"),
        "allocation_type": record.get("type"),
        "country": record.get("country"),
        "start_address": record.get("startAddress"),
        "end_address": record.get("endAddress"),
        "ip_version": record.get("ipVersion"),
        "parent_handle": record.get("parentHandle"),
        "cidrs": cidrs,
        "status": record.get("status", []),
        "events": events,
        "registrants": registrants,
    }


def _fetch_ip_asn(indicator: str) -> dict:
    """Fetch ASN and ISP information for a public IP address."""
    public_ip = _normalize_public_ip(indicator)

    response = requests.get(
        f"{IPWHOIS_BASE_URL}{public_ip}",
        headers={"Accept": "application/json"},
        timeout=IPWHOIS_TIMEOUT,
        allow_redirects=True,
    )
    response.raise_for_status()

    try:
        record = response.json()
    except ValueError:
        raise ValueError(
            "IP intelligence service returned invalid JSON."
        ) from None

    if not isinstance(record, dict):
        raise ValueError(
            "IP intelligence service returned an unexpected response."
        )

    if record.get("success") is not True:
        raise ValueError(
            "IP intelligence provider could not identify this IP."
        )

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

    if not isinstance(asn, (int, str)) or isinstance(asn, bool):
        asn = None

    return {
        "asn": asn,
        "organisation": safe_string(connection.get("org")),
        "isp": safe_string(connection.get("isp")),
        "domain": safe_string(connection.get("domain")),
    }


def _normalize_geo_record(record: dict, provider: str) -> dict:
    """Convert provider-specific GeoIP fields into one common structure."""
    if provider == "IPWHOIS":
        timezone_data = record.get("timezone")

        if isinstance(timezone_data, dict):
            timezone_value = timezone_data.get("id")
        else:
            timezone_value = timezone_data

        connection = record.get("connection")
        if not isinstance(connection, dict):
            connection = {}

        return {
            "city": record.get("city"),
            "region": record.get("region"),
            "country_name": record.get("country"),
            "country_code": record.get("country_code"),
            "latitude": record.get("latitude"),
            "longitude": record.get("longitude"),
            "timezone": timezone_value,
            "org": connection.get("org"),
            "provider": provider,
        }

    return {
        "city": record.get("city"),
        "region": record.get("region"),
        "country_name": record.get("country_name"),
        "country_code": record.get("country_code"),
        "latitude": record.get("latitude"),
        "longitude": record.get("longitude"),
        "timezone": record.get("timezone"),
        "org": record.get("org"),
        "provider": provider,
    }


def _fetch_ip_geo(indicator: str) -> dict:
    """
    Fetch approximate GeoIP information.

    Primary: IPWho.is
    Fallback: ipapi.co
    """
    public_ip = _normalize_public_ip(indicator)
    failures = []

    # Primary GeoIP provider: IPWho.is
    try:
        response = requests.get(
            f"{IPWHOIS_BASE_URL}{public_ip}",
            headers={"Accept": "application/json"},
            timeout=IPWHOIS_TIMEOUT,
            allow_redirects=True,
        )
        response.raise_for_status()

        record = response.json()

        if not isinstance(record, dict):
            raise ValueError("IPWho.is returned an invalid response.")

        if record.get("success") is not True:
            raise ValueError("IPWho.is could not identify this IP.")

        returned_ip = record.get("ip")

        if (
            not isinstance(returned_ip, str)
            or _normalize_public_ip(returned_ip) != public_ip
        ):
            raise ValueError("IPWho.is returned a mismatched IP.")

        return _normalize_geo_record(record, "IPWHOIS")

    except (requests.RequestException, ValueError) as exc:
        failures.append(f"IPWho.is: {type(exc).__name__}")

    # Fallback GeoIP provider: ipapi.co
    try:
        response = requests.get(
            f"{IP_GEO_BASE_URL}{public_ip}/json/",
            headers={"Accept": "application/json"},
            timeout=IP_GEO_TIMEOUT,
            allow_redirects=True,
        )
        response.raise_for_status()

        record = response.json()

        if not isinstance(record, dict):
            raise ValueError("ipapi.co returned an invalid response.")

        if record.get("error"):
            raise ValueError("ipapi.co returned a provider error.")

        returned_ip = record.get("ip")

        if (
            not isinstance(returned_ip, str)
            or _normalize_public_ip(returned_ip) != public_ip
        ):
            raise ValueError("ipapi.co returned a mismatched IP.")

        return _normalize_geo_record(record, "IPAPI")

    except (requests.RequestException, ValueError) as exc:
        failures.append(f"ipapi.co: {type(exc).__name__}")

    raise ValueError(
        "All GeoIP providers are unavailable. " + "; ".join(failures)
    )


def _parse_ip_geo(record: dict) -> dict:
    """Extract non-sensitive, approximate location information."""
    if not isinstance(record, dict):
        raise ValueError("Invalid GeoIP record.")

    return {
        "city": safe_string(record.get("city")),
        "region": safe_string(record.get("region")),
        "country": safe_string(record.get("country_name")),
        "country_code": safe_string(record.get("country_code")),
        "latitude": record.get("latitude"),
        "longitude": record.get("longitude"),
        "timezone": safe_string(record.get("timezone")),
        "network_organisation": safe_string(record.get("org")),
        "geo_provider": safe_string(record.get("provider")),
        "location_type": "Approximate IP-based location",
    }


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

    collected_at = datetime.now(timezone.utc).isoformat()
    results: list[FindingPayload] = []

    sources = [
        (
            "RDAP",
            "https://rdap.org/",
            _fetch_ip_rdap,
            _parse_ip_rdap,
        ),
        (
            "IPWHOIS",
            "https://ipwho.is/",
            _fetch_ip_asn,
            _parse_ip_asn,
        ),
        (
            "IPAPI_GEO",
            "https://ipwho.is/ (fallback: https://ipapi.co/)",
            _fetch_ip_geo,
            _parse_ip_geo,
        ),
    ]

    for source_name, source_url, fetcher, parser in sources:
        try:
            raw_record = fetcher(normalized_ip)
            finding = parser(raw_record)

            results.append(
                FindingPayload(
                    indicator=normalized_ip,
                    indicator_type=expected_type,
                    category=FindingCategory.EXTERNAL_INTELLIGENCE,
                    source=source_name,
                    collected_at_utc=collected_at,
                    status=FindingStatus.SUCCESS,
                    summary=(
                        f"{source_name} intelligence collected successfully."
                    ),
                    finding=finding,
                    confidence=Confidence.MEDIUM,
                    limitations=[],
                    source_url=source_url,
                )
            )

        except Exception as exc:
            results.append(
                FindingPayload(
                    indicator=normalized_ip,
                    indicator_type=expected_type,
                    category=FindingCategory.EXTERNAL_INTELLIGENCE,
                    source=source_name,
                    collected_at_utc=collected_at,
                    status=FindingStatus.UNAVAILABLE,
                    summary=(
                        f"{source_name} intelligence could not be collected."
                    ),
                    finding={},
                    confidence=Confidence.UNKNOWN,
                    limitations=[
                        f"Collection failed: {type(exc).__name__}: {exc}"
                    ],
                    source_url=source_url,
                )
            )

    return results
