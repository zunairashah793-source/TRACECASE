from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.error
import urllib.request

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from ..contracts import (
    Confidence,
    FindingCategory,
    FindingPayload,
    FindingStatus,
    IndicatorType,
)


# ============================================================
# CONFIGURATION
# ============================================================

SOURCE = "tls"
CENSYS_SOURCE = "censys"

TLS_TIMEOUT = 5.0
DEFAULT_PORT = 443
MAX_ADDRESSES = 20
MAX_SAN_ENTRIES = 100

CENSYS_API_BASE = (
    "https://api.platform.censys.io/v3/global/asset/certificate"
)
CENSYS_TIMEOUT = 20
CENSYS_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


# ============================================================
# COMMON HELPERS
# ============================================================

def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _make_payload(
    *,
    indicator: str,
    indicator_type: IndicatorType,
    status: FindingStatus,
    summary: str,
    finding: dict[str, Any],
    confidence: Confidence = Confidence.UNKNOWN,
    limitations: list[str] | None = None,
    source: str = SOURCE,
    source_url: str | None = None,
) -> FindingPayload:
    return FindingPayload(
        indicator=indicator,
        indicator_type=indicator_type,
        category=FindingCategory.EXTERNAL_INTELLIGENCE,
        source=source,
        collected_at_utc=_utc_now(),
        status=status,
        summary=summary,
        finding=finding,
        confidence=confidence,
        limitations=limitations or [],
        source_url=source_url,
    )


# ============================================================
# TARGET NORMALIZATION AND VALIDATION
# ============================================================


def _normalize_target(
    indicator: str,
    indicator_type: str,
) -> tuple[str, IndicatorType, int, bool]:
    """Validate and normalize a public TLS target."""

    if not isinstance(indicator, str) or not indicator.strip():
        raise ValueError("A TLS indicator is required.")

    value = indicator.strip()

    try:
        kind = IndicatorType(indicator_type)
    except (ValueError, TypeError):
        raise ValueError("Unsupported indicator type.") from None

    if kind == IndicatorType.TLS_CERTIFICATE:
        raw_fingerprint = value

        if raw_fingerprint.lower().startswith("sha256:"):
            raw_fingerprint = raw_fingerprint[7:]

        if re.fullmatch(r"[0-9a-fA-F]{64}", raw_fingerprint):
            fingerprint = raw_fingerprint.lower()
        elif re.fullmatch(
            r"(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}",
            raw_fingerprint,
        ):
            fingerprint = raw_fingerprint.replace(":", "").lower()
        else:
            raise ValueError(
                "A TLS certificate indicator must be a SHA-256 fingerprint."
            )

        return fingerprint, kind, DEFAULT_PORT, False

    port = DEFAULT_PORT

    if kind == IndicatorType.URL:
        try:
            parsed = urlsplit(value)

            if (
                parsed.scheme.lower() != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError

            host = parsed.hostname
            port = parsed.port if parsed.port is not None else DEFAULT_PORT

        except ValueError:
            raise ValueError(
                "TLS URL indicators must be valid HTTPS URLs."
            ) from None

    elif kind in (
        IndicatorType.IPV4,
        IndicatorType.IPV6,
        IndicatorType.DOMAIN,
        IndicatorType.SUBDOMAIN,
        IndicatorType.HOSTNAME,
    ):
        host = value
    else:
        raise ValueError(
            "TLS inspection requires an IP, domain, subdomain, "
            "hostname, HTTPS URL, or certificate fingerprint."
        )

    if not 1 <= port <= 65535:
        raise ValueError("Invalid TLS port.")

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None

    if address is not None:
        if not address.is_global:
            raise ValueError("Non-public IP addresses are not permitted.")

        if kind == IndicatorType.IPV4 and address.version != 4:
            raise ValueError("The indicator is not a valid IPv4 address.")

        if kind == IndicatorType.IPV6 and address.version != 6:
            raise ValueError("The indicator is not a valid IPv6 address.")

        if kind not in (
            IndicatorType.IPV4,
            IndicatorType.IPV6,
            IndicatorType.URL,
        ):
            raise ValueError(
                "IP addresses require an IP or URL indicator type."
            )

        return str(address), kind, port, True

    if kind in (IndicatorType.IPV4, IndicatorType.IPV6):
        raise ValueError("The indicator is not a valid IP address.")

    host = host.rstrip(".")

    try:
        normalized = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid internationalized hostname.") from None

    if not normalized or len(normalized) > 253:
        raise ValueError("Invalid hostname length.")

    labels = normalized.split(".")

    if len(labels) < 2:
        raise ValueError("Single-label hostnames are not permitted.")

    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Invalid hostname.")

    blocked_suffixes = (
        "localhost",
        "local",
        "internal",
        "test",
        "invalid",
        "example",
    )

    if any(
        normalized == suffix or normalized.endswith("." + suffix)
        for suffix in blocked_suffixes
    ):
        raise ValueError("Reserved or local hostname suffixes are not permitted.")

    return normalized, kind, port, False


# ============================================================
# PUBLIC DNS VALIDATION
# ============================================================


def _resolve_public_addresses(
    host: str,
    port: int,
    is_ip: bool,
) -> list[str]:
    """Resolve a host and reject non-public or excessive DNS answers."""

    if is_ip:
        address = ipaddress.ip_address(host)

        if not address.is_global:
            raise ValueError("Non-public IP addresses are not permitted.")

        return [str(address)]

    try:
        results = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
        )
    except OSError:
        raise OSError("Hostname resolution failed.") from None

    if len(results) > MAX_ADDRESSES:
        raise ValueError("The hostname returned too many DNS answers.")

    addresses: list[str] = []

    for result in results:
        try:
            address_text = result[4][0]
            address = ipaddress.ip_address(address_text)
        except (IndexError, TypeError, ValueError):
            continue

        if not address.is_global:
            raise ValueError(
                "The hostname resolves to a non-public IP address."
            )

        normalized = str(address)

        if normalized not in addresses:
            addresses.append(normalized)

    if not addresses:
        raise OSError("No usable IP addresses were returned.")

    return addresses


# ============================================================
# LIVE TLS CERTIFICATE INSPECTION
# ============================================================

def _format_name(name: Any) -> list[dict[str, str]]:
    """Convert a certificate distinguished name into JSON-safe entries."""

    formatted: list[dict[str, str]] = []

    if not isinstance(name, (tuple, list)):
        return formatted

    for rdn in name:
        if not isinstance(rdn, (tuple, list)):
            continue

        for item in rdn:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue

            key, value = item

            formatted.append(
                {
                    "name": str(key),
                    "value": str(value),
                }
            )

    return formatted


def _inspect_certificate(
    *,
    host: str,
    address: str,
    port: int,
    is_ip: bool,
) -> dict[str, Any]:
    """Connect to one validated public address and inspect its certificate."""

    del is_ip  # Retained in the internal interface for compatibility.

    context = ssl.create_default_context()

    with socket.create_connection(
        (address, port),
        timeout=TLS_TIMEOUT,
    ) as raw_socket:

        with context.wrap_socket(
            raw_socket,
            server_hostname=host,
        ) as tls_socket:

            certificate_der = tls_socket.getpeercert(binary_form=True)
            certificate = tls_socket.getpeercert()

            if not certificate_der or not certificate:
                raise ssl.SSLError(
                    "The peer did not provide a usable certificate."
                )

            fingerprint = hashlib.sha256(
                certificate_der
            ).hexdigest()

            raw_sans = certificate.get("subjectAltName") or []

            if not isinstance(raw_sans, (tuple, list)):
                raw_sans = []

            sans: list[dict[str, str]] = []

            for entry in raw_sans[:MAX_SAN_ENTRIES]:
                if not isinstance(entry, (tuple, list)) or len(entry) != 2:
                    continue

                sans.append(
                    {
                        "type": str(entry[0]),
                        "value": str(entry[1]),
                    }
                )

            not_before_raw = certificate.get("notBefore")
            not_after_raw = certificate.get("notAfter")

            not_before: str | None = None
            not_after: str | None = None

            if isinstance(not_before_raw, str):
                not_before = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(not_before_raw),
                    timezone.utc,
                ).strftime("%Y-%m-%dT%H:%M:%SZ")

            if isinstance(not_after_raw, str):
                not_after = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(not_after_raw),
                    timezone.utc,
                ).strftime("%Y-%m-%dT%H:%M:%SZ")

            cipher_info = tls_socket.cipher()

            return {
                "host": host,
                "connected_address": address,
                "port": port,
                "tls_version": tls_socket.version(),
                "cipher": cipher_info[0] if cipher_info else None,
                "certificate": {
                    "sha256_fingerprint": fingerprint,
                    "serial_number": certificate.get("serialNumber"),
                    "subject": _format_name(
                        certificate.get("subject", ())
                    ),
                    "issuer": _format_name(
                        certificate.get("issuer", ())
                    ),
                    "not_before_utc": not_before,
                    "not_after_utc": not_after,
                    "subject_alt_names": sans,
                    "subject_alt_names_truncated": (
                        len(raw_sans) > MAX_SAN_ENTRIES
                    ),
                    "version": certificate.get("version"),
                    "hostname_verification": "passed",
                    "chain_verification": "passed",
                },
            }


# ============================================================
# CENSYS PASSIVE CERTIFICATE LOOKUP
# ============================================================

def _censys_unavailable(
    fingerprint: str,
    kind: IndicatorType,
    endpoint: str,
    reason: str,
    http_status: int | None = None,
    provider_configured: bool = False,
) -> list[FindingPayload]:
    """Return an unavailable result without exposing credentials."""

    finding: dict[str, Any] = {
        "sha256_fingerprint": fingerprint,
        "provider": CENSYS_SOURCE,
        "lookup_mode": "passive",
        "provider_configured": provider_configured,
    }

    if http_status is not None:
        finding["http_status"] = http_status

    return [
        _make_payload(
            indicator=fingerprint,
            indicator_type=kind,
            status=FindingStatus.UNAVAILABLE,
            summary="Censys certificate lookup is unavailable.",
            finding=finding,
            source=CENSYS_SOURCE,
            source_url=endpoint,
            limitations=[
                reason,
                "No live TLS connection was attempted because "
                "the indicator is a certificate fingerprint.",
            ],
        )
    ]


def _censys_error(
    fingerprint: str,
    kind: IndicatorType,
    endpoint: str,
    reason: str,
) -> list[FindingPayload]:
    return [
        _make_payload(
            indicator=fingerprint,
            indicator_type=kind,
            status=FindingStatus.ERROR,
            summary="Censys certificate lookup failed.",
            finding={
                "sha256_fingerprint": fingerprint,
                "provider": CENSYS_SOURCE,
                "lookup_mode": "passive",
            },
            source=CENSYS_SOURCE,
            source_url=endpoint,
            limitations=[reason],
        )
    ]



class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent authenticated Censys requests from following redirects."""

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        return None


def _collect_fingerprint_lookup(
    fingerprint: str,
    kind: IndicatorType,
) -> list[FindingPayload]:
    """Retrieve certificate intelligence using the Censys Platform API."""

    token = os.environ.get("CENSYS_API_TOKEN", "").strip()
    endpoint = f"{CENSYS_API_BASE}/{fingerprint}"

    if not token:
        return _censys_unavailable(
            fingerprint,
            kind,
            endpoint,
            "CENSYS_API_TOKEN is not configured.",
            provider_configured=False,
        )

    request = urllib.request.Request(
        endpoint,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        opener = urllib.request.build_opener(_NoRedirectHandler())

        with opener.open(
            request,
            timeout=CENSYS_TIMEOUT,
        ) as response:

            if response.status != 200:
                return _censys_error(
                    fingerprint,
                    kind,
                    endpoint,
                    "Censys returned an unexpected HTTP status.",
                )

            raw_data = response.read(
                CENSYS_MAX_RESPONSE_BYTES + 1
            )

            if len(raw_data) > CENSYS_MAX_RESPONSE_BYTES:
                return _censys_error(
                    fingerprint,
                    kind,
                    endpoint,
                    "Censys response exceeded the configured size limit.",
                )

        data: Any = json.loads(raw_data.decode("utf-8"))

    except urllib.error.HTTPError as exc:

        if exc.code in (401, 403, 404):
            return _censys_unavailable(
                fingerprint,
                kind,
                endpoint,
                f"Censys returned HTTP {exc.code}.",
                http_status=exc.code,
                provider_configured=True,
            )

        return _censys_error(
            fingerprint,
            kind,
            endpoint,
            f"Censys API returned HTTP {exc.code}.",
        )

    except json.JSONDecodeError:
        return _censys_error(
            fingerprint,
            kind,
            endpoint,
            "Censys returned invalid JSON.",
        )

    except (OSError, TimeoutError, UnicodeError, ValueError, TypeError):
        return _censys_error(
            fingerprint,
            kind,
            endpoint,
            "The Censys response could not be retrieved or processed.",
        )

    if not isinstance(data, dict):
        return _censys_error(
            fingerprint,
            kind,
            endpoint,
            "Censys returned an unexpected response structure.",
        )

    result = data.get("result")

    if not isinstance(result, dict):
        return _censys_error(
            fingerprint,
            kind,
            endpoint,
            "The expected result object was missing.",
        )

    resource = result.get("resource")

    if not isinstance(resource, dict):
        return _censys_error(
            fingerprint,
            kind,
            endpoint,
            "The expected result.resource certificate record was missing.",
        )

    returned_fingerprint = str(
        resource.get("fingerprint_sha256") or ""
    ).lower()

    if returned_fingerprint != fingerprint:
        return _censys_error(
            fingerprint,
            kind,
            endpoint,
            "The returned certificate fingerprint did not match the requested fingerprint.",
        )

    parsed = resource.get("parsed")

    if not isinstance(parsed, dict):
        parsed = {}

    parsed_extensions = parsed.get("extensions")

    if not isinstance(parsed_extensions, dict):
        parsed_extensions = {}

    certificate_data: dict[str, Any] = {
        "sha256_fingerprint": resource.get("fingerprint_sha256"),
        "sha1_fingerprint": resource.get("fingerprint_sha1"),
        "md5_fingerprint": resource.get("fingerprint_md5"),
        "tbs_fingerprint_sha256": resource.get(
            "tbs_fingerprint_sha256"
        ),
        "subject_dn": parsed.get("subject_dn"),
        "issuer_dn": parsed.get("issuer_dn"),
        "subject": parsed.get("subject"),
        "issuer": parsed.get("issuer"),
        "serial_number": parsed.get("serial_number"),
        "serial_number_hex": parsed.get("serial_number_hex"),
        "version": parsed.get("version"),
        "validity_period": parsed.get("validity_period"),
        "subject_alt_names": parsed_extensions.get(
            "subject_alt_name"
        ),
        "names": resource.get("names"),
        "validation_level": resource.get("validation_level"),
        "validation": resource.get("validation"),
        "revocation": resource.get("revocation"),
        "certificate_transparency": resource.get("ct"),
        "zlint": resource.get("zlint"),
        "parse_status": resource.get("parse_status"),
        "added_at": resource.get("added_at"),
        "modified_at": resource.get("modified_at"),
        "validated_at": resource.get("validated_at"),
    }

    return [
        _make_payload(
            indicator=fingerprint,
            indicator_type=kind,
            status=FindingStatus.SUCCESS,
            summary=(
                "Censys certificate intelligence retrieved successfully."
            ),
            finding={
                "provider": CENSYS_SOURCE,
                "lookup_mode": "passive",
                "provider_configured": True,
                "certificate": certificate_data,
            },
            confidence=Confidence.HIGH,
            source=CENSYS_SOURCE,
            source_url=endpoint,
            limitations=[
                "Results reflect certificate intelligence collected by Censys.",
                "The record may not represent the current live endpoint.",
                "A certificate record does not establish that a website is trustworthy.",
            ],
        )
    ]


# ============================================================
# PUBLIC TLS COLLECTOR
# ============================================================


def collect_tls_intel(
    *,
    indicator: str,
    indicator_type: str,
) -> list[FindingPayload]:
    """Collect TLS metadata from a validated public endpoint or Censys."""

    host, kind, port, is_ip = _normalize_target(
        indicator,
        indicator_type,
    )

    if kind == IndicatorType.TLS_CERTIFICATE:
        return _collect_fingerprint_lookup(host, kind)

    try:
        addresses = _resolve_public_addresses(
            host,
            port,
            is_ip,
        )
    except ValueError:
        raise
    except OSError as exc:
        return [
            _make_payload(
                indicator=host,
                indicator_type=kind,
                status=FindingStatus.ERROR,
                summary="TLS endpoint could not be resolved.",
                finding={
                    "host": host,
                    "port": port,
                    "error_type": type(exc).__name__,
                },
                limitations=[
                    "TLS inspection did not proceed because public DNS "
                    "resolution failed."
                ],
            )
        ]

    successes: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for address in addresses:
        try:
            result = _inspect_certificate(
                host=host,
                address=address,
                port=port,
                is_ip=is_ip,
            )
            successes.append(result)

        except (OSError, ssl.SSLError, TimeoutError) as exc:
            errors.append({
                "address": address,
                "error_type": type(exc).__name__,
            })

    if successes:
        partial = bool(errors)
        primary_result = dict(successes[0])

        # Preserve the original evidence fields while adding multi-address
        # evidence for the investigation report.
        primary_result.update({
            "resolved_addresses": addresses,
            "successful_inspections": len(successes),
            "inspection_errors": errors,
            "certificate_inspections": successes,
        })

        limitations = [
            "Inspection reflects certificates presented at collection time.",
            "A successful handshake does not establish that the website "
            "or service is trustworthy.",
        ]

        if partial:
            limitations.append(
                "Some resolved public addresses could not complete TLS inspection."
            )

        return [
            _make_payload(
                indicator=host,
                indicator_type=kind,
                status=(
                    FindingStatus.PARTIAL if partial else FindingStatus.SUCCESS
                ),
                summary=(
                    f"TLS inspection completed with partial results for "
                    f"{host}:{port}."
                    if partial
                    else f"TLS certificate inspected successfully for {host}:{port}."
                ),
                finding=primary_result,
                confidence=(
                    Confidence.MEDIUM if partial else Confidence.HIGH
                ),
                limitations=limitations,
            )
        ]

    return [
        _make_payload(
            indicator=host,
            indicator_type=kind,
            status=FindingStatus.ERROR,
            summary=f"TLS certificate inspection failed for {host}:{port}.",
            finding={
                "host": host,
                "port": port,
                "attempted_addresses": addresses,
                "error_types": sorted({
                    item["error_type"] for item in errors
                }),
                "inspection_errors": errors,
            },
            limitations=[
                "No certificate metadata was collected.",
                "The endpoint may be unreachable, may reject TLS, "
                "or may present a certificate that fails verification.",
            ],
        )
    ]
