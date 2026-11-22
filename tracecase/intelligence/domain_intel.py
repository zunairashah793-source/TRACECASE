
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

import dns.exception
import dns.resolver

from ..contracts import (
    Confidence,
    FindingCategory,
    FindingPayload,
    FindingStatus,
    IndicatorType,
)


DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")
DNS_TIMEOUT = 2.0
DNS_LIFETIME = 5.0
MAX_RECORDS_PER_TYPE = 50
MAX_TXT_LENGTH = 512

SOURCE = "dns"


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _normalize_domain(indicator: str, indicator_type: str) -> str:
    """Validate and normalize a supported domain-like indicator."""

    if not isinstance(indicator, str) or not indicator.strip():
        raise ValueError("A domain indicator is required.")

    value = indicator.strip()

    try:
        kind = IndicatorType(indicator_type)
    except (ValueError, TypeError):
        raise ValueError("Unsupported indicator type.") from None

    if kind == IndicatorType.URL:
        try:
            parsed = urlsplit(value)

            if parsed.scheme.lower() not in ("http", "https"):
                raise ValueError

            if not parsed.hostname or parsed.username or parsed.password:
                raise ValueError

            _ = parsed.port
            value = parsed.hostname

        except ValueError:
            raise ValueError(
                "Only valid HTTP or HTTPS URLs are supported."
            ) from None

    elif kind not in (
        IndicatorType.DOMAIN,
        IndicatorType.SUBDOMAIN,
        IndicatorType.HOSTNAME,
    ):
        raise ValueError(
            "This collector requires a domain, subdomain, hostname, or URL."
        )

    value = value.rstrip(".")

    if not value or "/" in value or ":" in value:
        raise ValueError("Invalid domain name.")

    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError(
            "IP addresses must use the IP intelligence collector."
        )

    try:
        normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError(
            "Invalid internationalized domain name."
        ) from None

    if len(normalized) > 253:
        raise ValueError("Domain name is too long.")

    labels = normalized.split(".")

    if len(labels) < 2:
        raise ValueError(
            "A fully qualified public domain name is required."
        )

    for label in labels:
        if (
            not label
            or len(label) > 63
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label,
            )
        ):
            raise ValueError("Invalid domain label.")

    special_suffixes = (
        ".localhost",
        ".local",
        ".test",
        ".invalid",
        ".example",
    )

    if normalized == "localhost" or normalized.endswith(special_suffixes):
        raise ValueError(
            "Local or reserved domain names are not supported."
        )

    return normalized


def _extract_record(record_type: str, record) -> str:
    """Convert a DNS answer into a JSON-safe string."""

    if record_type in ("A", "AAAA"):
        return str(ipaddress.ip_address(record.address))

    if record_type == "MX":
        return f"{record.preference} {record.exchange.to_text()}"

    if record_type == "NS":
        return record.target.to_text()

    if record_type == "TXT":
        parts = getattr(record, "strings", ())
        text = b"".join(parts).decode(
            "utf-8",
            errors="replace",
        )
        return text[:MAX_TXT_LENGTH]

    return str(record)


def _query_dns(name: str) -> tuple[dict, dict, list[str]]:
    """Collect bounded DNS observations and query outcomes."""

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME

    records = {}
    outcomes = {}
    limitations = []

    for record_type in DNS_RECORD_TYPES:
        try:
            answer = resolver.resolve(
                name,
                record_type,
                lifetime=DNS_LIFETIME,
                search=False,
                raise_on_no_answer=False,
            )

            rrset = getattr(answer, "rrset", None)

            if rrset is None:
                records[record_type] = []
                outcomes[record_type] = "no_answer"
                continue

            values = [
                _extract_record(record_type, item)
                for item in list(answer)[:MAX_RECORDS_PER_TYPE]
            ]

            records[record_type] = values
            outcomes[record_type] = "success"

        except dns.resolver.NXDOMAIN:
            records[record_type] = []
            outcomes[record_type] = "nxdomain"
            limitations.append(
                "The DNS resolver reported that the domain does not exist."
            )
            break

        except (
            dns.resolver.NoNameservers,
            dns.resolver.LifetimeTimeout,
            dns.exception.Timeout,
        ):
            records[record_type] = []
            outcomes[record_type] = "unavailable"
            limitations.append(
                f"The DNS {record_type} lookup timed out "
                "or its nameservers were unavailable."
            )

        except Exception:
            records[record_type] = []
            outcomes[record_type] = "error"
            limitations.append(
                f"The DNS {record_type} lookup failed unexpectedly."
            )

    return records, outcomes, limitations


def collect_domain_intel(
    *,
    indicator: str,
    indicator_type: str,
) -> list[FindingPayload]:
    """Collect DNS intelligence for a public domain-like indicator."""

    normalized_domain = _normalize_domain(
        indicator,
        indicator_type,
    )

    records, outcomes, limitations = _query_dns(normalized_domain)

    successful_types = sum(
        1
        for outcome in outcomes.values()
        if outcome == "success"
    )

    failed_types = sum(
        1
        for outcome in outcomes.values()
        if outcome in ("unavailable", "error")
    )

    has_nxdomain = any(
        outcome == "nxdomain"
        for outcome in outcomes.values()
    )

    if has_nxdomain:
        status = FindingStatus.SUCCESS
        confidence = Confidence.HIGH
        summary = (
            f"DNS reported that {normalized_domain} does not exist."
        )

    elif successful_types and failed_types:
        status = FindingStatus.PARTIAL
        confidence = Confidence.MEDIUM
        summary = (
            f"DNS returned some records for {normalized_domain}; "
            "some record lookups were unavailable."
        )

    elif successful_types:
        status = FindingStatus.SUCCESS
        confidence = Confidence.MEDIUM
        summary = (
            f"DNS records were collected for {normalized_domain}."
        )

    else:
        status = FindingStatus.UNAVAILABLE
        confidence = Confidence.UNKNOWN
        summary = (
            f"No DNS records could be collected for {normalized_domain}."
        )

        if not limitations:
            limitations.append(
                "The DNS resolver returned no records "
                "for the requested record types."
            )

    payload = FindingPayload(
        indicator=indicator,
        indicator_type=IndicatorType(indicator_type),
        category=FindingCategory.EXTERNAL_INTELLIGENCE,
        source=SOURCE,
        collected_at_utc=_utc_now(),
        status=status,
        summary=summary,
        finding={
            "queried_domain": normalized_domain,
            "records": records,
            "query_outcomes": outcomes,
        },
        confidence=confidence,
        limitations=limitations,
        source_url=None,
    )

    return [payload]
