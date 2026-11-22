
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


SOURCE_NAME = "tls_intel"
DEFAULT_TLS_PORT = 443
CONNECT_TIMEOUT = 5
MAX_DNS_ANSWERS = 20
MAX_CENSYS_RESPONSE_BYTES = 2 * 1024 * 1024

BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".test",
    ".invalid",
    ".example",
)

SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
COLON_FINGERPRINT_PATTERN = re.compile(
    r"^(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}$"
)


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _normalize_fingerprint(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid certificate fingerprint.")

    normalized = value.strip()

    if COLON_FINGERPRINT_PATTERN.fullmatch(normalized):
        normalized = normalized.replace(":", "")

    if not SHA256_PATTERN.fullmatch(normalized):
        raise ValueError("A valid SHA-256 fingerprint is required.")

    return normalized.lower()


def _normalize_domain(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid hostname.")

    value = value.strip().rstrip(".")

    if not value or len(value) > 253:
        raise ValueError("Invalid hostname.")

    try:
        hostname = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized hostname.") from exc

    if "." not in hostname:
        raise ValueError("Single-label hostnames are not allowed.")

    if any(hostname.endswith(suffix) for suffix in BLOCKED_SUFFIXES):
        raise ValueError("Local or reserved hostname is not allowed.")

    labels = hostname.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
        ):
            raise ValueError("Invalid hostname.")

    return hostname


def _validate_public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("Invalid IP address.") from exc

    if not address.is_global:
        raise ValueError("Private or non-global IP addresses are not allowed.")

    return str(address)


def _normalize_target(
    indicator: str,
    indicator_type: str,
) -> dict[str, Any]:

    try:
        kind = IndicatorType(indicator_type)
    except (ValueError, TypeError) as exc:
        raise ValueError("Unsupported indicator type.") from exc

    if not isinstance(indicator, str) or not indicator.strip():
        raise ValueError("Indicator cannot be empty.")

    value = indicator.strip()

    if kind == IndicatorType.TLS_CERTIFICATE:
        return {
            "mode": "fingerprint",
            "fingerprint": _normalize_fingerprint(value),
        }

    if kind == IndicatorType.URL:
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Invalid HTTPS URL.") from exc

        if parsed.scheme.lower() != "https":
            raise ValueError("Only HTTPS URLs are supported.")

        if not hostname:
            raise ValueError("URL must contain a hostname.")

        if parsed.username or parsed.password:
            raise ValueError("URLs containing credentials are not allowed.")

        # Only use the default when no port was supplied.
        if port is None:
            port = DEFAULT_TLS_PORT

        if not 1 <= port <= 65535:
            raise ValueError("Invalid TLS port.")

        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            hostname = _normalize_domain(hostname)
            is_ip = False

        if is_ip:
            hostname = _validate_public_ip(hostname)

        return {
            "mode": "connection",
            "hostname": hostname,
            "port": port,
            "is_ip": is_ip,
        }

    if kind in (IndicatorType.IPV4, IndicatorType.IPV6):
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("Invalid IP address.") from exc

        if kind == IndicatorType.IPV4 and address.version != 4:
            raise ValueError("Expected an IPv4 address.")

        if kind == IndicatorType.IPV6 and address.version != 6:
            raise ValueError("Expected an IPv6 address.")

        hostname = _validate_public_ip(value)

        return {
            "mode": "connection",
            "hostname": hostname,
            "port": DEFAULT_TLS_PORT,
            "is_ip": True,
        }

    if kind in (
        IndicatorType.DOMAIN,
        IndicatorType.SUBDOMAIN,
        IndicatorType.HOSTNAME,
    ):
        hostname = _normalize_domain(value)

        return {
            "mode": "connection",
            "hostname": hostname,
            "port": DEFAULT_TLS_PORT,
            "is_ip": False,
        }

    raise ValueError("Unsupported indicator type.")


def _resolve_public_addresses(hostname: str) -> list[str]:
    try:
        answers = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise RuntimeError("DNS resolution failed.") from exc

    if not answers:
        raise RuntimeError("DNS returned no addresses.")

    if len(answers) > MAX_DNS_ANSWERS:
        raise RuntimeError("DNS returned too many addresses.")

    addresses: list[str] = []

    for answer in answers:
        raw_address = answer[4][0]

        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError:
            continue

        if not address.is_global:
            raise ValueError(
                "DNS resolved to a private or non-global address."
            )

        normalized = str(address)

        if normalized not in addresses:
            addresses.append(normalized)

    if not addresses:
        raise RuntimeError("DNS returned no valid public addresses.")

    return addresses


def _inspect_tls(
    *,
    hostname: str,
    address: str,
    port: int,
    timeout: int = CONNECT_TIMEOUT,
) -> dict[str, Any]:

    context = ssl.create_default_context()
    raw_socket = None
    tls_socket = None

    try:
        raw_socket = socket.create_connection(
            (address, port),
            timeout=timeout,
        )

        tls_socket = context.wrap_socket(
            raw_socket,
            server_hostname=hostname,
        )

        # Handle the optional return type of getpeercert().
        certificate = tls_socket.getpeercert() or {}
        certificate_der = tls_socket.getpeercert(binary_form=True)

        if not certificate_der:
            raise RuntimeError("Server did not provide a certificate.")

        fingerprint = hashlib.sha256(
            certificate_der
        ).hexdigest()

        cipher = tls_socket.cipher()

        subject_alt_names = [
            value
            for name, value in certificate.get("subjectAltName", [])
            if name in ("DNS", "IP Address")
        ]

        return {
            "hostname": hostname,
            "connected_ip": address,
            "port": port,
            "tls_version": tls_socket.version(),
            "cipher": cipher[0] if cipher else None,
            "cipher_protocol": cipher[1] if cipher else None,
            "hostname_verification": "passed",
            "certificate_chain_verification": "passed",
            "certificate_sha256": fingerprint,
            "certificate_subject": certificate.get("subject"),
            "certificate_issuer": certificate.get("issuer"),
            "certificate_not_before": certificate.get("notBefore"),
            "certificate_not_after": certificate.get("notAfter"),
            "subject_alt_names": subject_alt_names,
        }

    finally:
        if tls_socket is not None:
            tls_socket.close()
        elif raw_socket is not None:
            raw_socket.close()


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):

    def redirect_request(
        self,
        request,
        file_pointer,
        code,
        message,
        headers,
        new_url,
    ):
        raise urllib.error.HTTPError(
            request.full_url,
            code,
            "Censys redirect blocked.",
            headers,
            file_pointer,
        )


def _extract_censys_fingerprint(data: Any) -> str | None:
    if isinstance(data, dict):

        for key in (
            "fingerprint",
            "fingerprint_sha256",
            "sha256_fingerprint",
        ):
            value = data.get(key)

            if isinstance(value, str):
                candidate = value.replace(":", "").lower()

                if SHA256_PATTERN.fullmatch(candidate):
                    return candidate

        for value in data.values():
            result = _extract_censys_fingerprint(value)

            if result:
                return result

    elif isinstance(data, list):
        for value in data:
            result = _extract_censys_fingerprint(value)

            if result:
                return result

    return None


def _lookup_censys_fingerprint(
    fingerprint: str,
) -> dict[str, Any]:

    token = os.environ.get("CENSYS_API_TOKEN")

    if not token:
        raise RuntimeError("Censys API token is not configured.")

    url = (
        "https://search.censys.io/api/v2/certificates/"
        f"{fingerprint}"
    )

    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "TRACECASE/1.0",
        },
        method="GET",
    )

    opener = urllib.request.build_opener(
        _NoRedirectHandler()
    )

    try:
        with opener.open(
            request,
            timeout=CONNECT_TIMEOUT,
        ) as response:

            content = response.read(
                MAX_CENSYS_RESPONSE_BYTES + 1
            )

            if len(content) > MAX_CENSYS_RESPONSE_BYTES:
                raise RuntimeError(
                    "Censys response exceeded the size limit."
                )

            data = json.loads(content.decode("utf-8"))

            if not isinstance(data, dict):
                raise RuntimeError("Invalid Censys response.")

            returned_fingerprint = _extract_censys_fingerprint(data)

            if not returned_fingerprint:
                raise RuntimeError(
                    "Censys response did not contain a SHA-256 fingerprint."
                )

            return {
                "fingerprint": returned_fingerprint,
                "result": data,
            }

    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise RuntimeError("Censys redirect blocked.") from exc

        raise RuntimeError(
            f"Censys returned HTTP status {exc.code}."
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError("Censys connection failed.") from exc

    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("Invalid Censys response data.") from exc


def _make_finding(
    *,
    indicator: str,
    indicator_type: IndicatorType,
    status: FindingStatus,
    summary: str,
    finding: dict[str, Any],
    confidence: Confidence = Confidence.UNKNOWN,
    limitations: list[str] | None = None,
    source_url: str | None = None,
) -> FindingPayload:

    return FindingPayload(
        indicator=indicator,
        indicator_type=indicator_type,
        category=FindingCategory.EXTERNAL_INTELLIGENCE,
        source=SOURCE_NAME,
        collected_at_utc=_utc_now(),
        status=status,
        summary=summary,
        finding=finding,
        confidence=confidence,
        limitations=limitations or [],
        source_url=source_url,
    )


def collect_tls_intel(
    *,
    indicator: str,
    indicator_type: str,
) -> list[FindingPayload]:

    try:
        normalized = _normalize_target(
            indicator,
            indicator_type,
        )

    except (ValueError, TypeError) as exc:

        try:
            fallback_type = IndicatorType(indicator_type)
        except (ValueError, TypeError):
            fallback_type = IndicatorType.HOSTNAME

        return [
            _make_finding(
                indicator=str(indicator),
                indicator_type=fallback_type,
                status=FindingStatus.ERROR,
                summary="TLS target validation failed.",
                finding={"error": str(exc)},
                limitations=[
                    "The supplied target could not be validated."
                ],
            )
        ]

    actual_type = IndicatorType(indicator_type)

    # Passive certificate fingerprint lookup.
    if normalized["mode"] == "fingerprint":

        fingerprint = normalized["fingerprint"]

        try:
            result = _lookup_censys_fingerprint(fingerprint)

            returned_fingerprint = result.get("fingerprint")

            if (
                not isinstance(returned_fingerprint, str)
                or returned_fingerprint.lower() != fingerprint
            ):
                raise RuntimeError(
                    "Censys returned a mismatched certificate fingerprint."
                )

            return [
                _make_finding(
                    indicator=indicator,
                    indicator_type=actual_type,
                    status=FindingStatus.SUCCESS,
                    summary="Certificate fingerprint lookup completed.",
                    finding={
                        "requested_sha256_fingerprint": fingerprint,
                        "result": result.get("result", {}),
                    },
                    confidence=Confidence.MEDIUM,
                    source_url=(
                        "https://search.censys.io/certificates/"
                        f"{fingerprint}"
                    ),
                )
            ]

        except RuntimeError as exc:

            if "not configured" in str(exc).lower():
                return [
                    _make_finding(
                        indicator=indicator,
                        indicator_type=actual_type,
                        status=FindingStatus.UNAVAILABLE,
                        summary="Passive certificate lookup is unavailable.",
                        finding={
                            "requested_sha256_fingerprint": fingerprint,
                            "error": str(exc),
                        },
                        limitations=[
                            "CENSYS_API_TOKEN is not configured."
                        ],
                    )
                ]

            return [
                _make_finding(
                    indicator=indicator,
                    indicator_type=actual_type,
                    status=FindingStatus.ERROR,
                    summary="Passive certificate lookup failed.",
                    finding={
                        "requested_sha256_fingerprint": fingerprint,
                        "error": str(exc),
                    },
                    limitations=[
                        "The certificate lookup could not be completed."
                    ],
                )
            ]

    # Live TLS inspection.
    # Public-target use remains subject to the project's ADR-008 decision.
    hostname = normalized["hostname"]
    port = normalized["port"]

    try:
        addresses = (
            [hostname]
            if normalized["is_ip"]
            else _resolve_public_addresses(hostname)
        )

        successful_inspections: list[dict[str, Any]] = []
        inspection_errors: list[dict[str, str]] = []

        for address in addresses:
            try:
                result = _inspect_tls(
                    hostname=hostname,
                    address=address,
                    port=port,
                )

                successful_inspections.append(result)

            except (OSError, ssl.SSLError, RuntimeError, ValueError) as exc:
                inspection_errors.append(
                    {
                        "address": address,
                        "error": str(exc),
                    }
                )

        finding_data = {
            "hostname": hostname,
            "port": port,
            "resolved_addresses": addresses,
            "successful_inspections": successful_inspections,
            "inspection_errors": inspection_errors,
        }

        if successful_inspections and inspection_errors:
            status = FindingStatus.PARTIAL
            summary = "TLS inspection partially completed."

        elif successful_inspections:
            status = FindingStatus.SUCCESS
            summary = "TLS inspection completed successfully."

        else:
            status = FindingStatus.ERROR
            summary = "TLS inspection failed for all resolved addresses."

        confidence = (
            Confidence.MEDIUM
            if successful_inspections
            else Confidence.UNKNOWN
        )

        limitations = []

        if inspection_errors:
            limitations.append(
                "One or more resolved addresses could not be inspected."
            )

        return [
            _make_finding(
                indicator=indicator,
                indicator_type=actual_type,
                status=status,
                summary=summary,
                finding=finding_data,
                confidence=confidence,
                limitations=limitations,
            )
        ]

    except (ValueError, RuntimeError, OSError) as exc:

        return [
            _make_finding(
                indicator=indicator,
                indicator_type=actual_type,
                status=FindingStatus.ERROR,
                summary="TLS inspection could not be completed.",
                finding={
                    "hostname": hostname,
                    "port": port,
                    "error": str(exc),
                },
                limitations=[
                    "Target validation, DNS resolution, or TLS inspection failed."
                ],
            )
        ]
