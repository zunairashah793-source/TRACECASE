
from __future__ import annotations
from email.message import Message

import socket
import urllib.error

import pytest

from tracecase.contracts import (
    FindingStatus,
    IndicatorType,
)
from tracecase.intelligence import tls_intel


# ---------------------------------------------------------
# Target normalization
# ---------------------------------------------------------

def test_normalize_domain():
    result = tls_intel._normalize_target(
        "Example.COM",
        IndicatorType.DOMAIN.value,
    )

    assert result["mode"] == "connection"
    assert result["hostname"] == "example.com"
    assert result["port"] == 443
    assert result["is_ip"] is False


def test_normalize_https_url_with_custom_port():
    result = tls_intel._normalize_target(
        "https://example.com:8443/path",
        IndicatorType.URL.value,
    )

    assert result["hostname"] == "example.com"
    assert result["port"] == 8443


def test_reject_http_url():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "http://example.com",
            IndicatorType.URL.value,
        )


def test_reject_url_with_credentials():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "https://user:password@example.com",
            IndicatorType.URL.value,
        )


def test_reject_invalid_url_port():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "https://example.com:70000",
            IndicatorType.URL.value,
        )


def test_reject_port_zero():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "https://example.com:0",
            IndicatorType.URL.value,
        )


def test_reject_private_ip():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "192.168.1.10",
            IndicatorType.IPV4.value,
        )


def test_reject_wrong_ip_version():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "8.8.8.8",
            IndicatorType.IPV6.value,
        )


def test_reject_single_label_hostname():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "localhost",
            IndicatorType.HOSTNAME.value,
        )


def test_reject_local_suffix():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "server.local",
            IndicatorType.HOSTNAME.value,
        )


# ---------------------------------------------------------
# Certificate fingerprint validation
# ---------------------------------------------------------

def test_normalize_sha256_fingerprint():
    fingerprint = "A" * 64

    result = tls_intel._normalize_target(
        fingerprint,
        IndicatorType.TLS_CERTIFICATE.value,
    )

    assert result["mode"] == "fingerprint"
    assert result["fingerprint"] == "a" * 64


def test_normalize_colon_separated_fingerprint():
    fingerprint = ":".join(["AA"] * 32)

    result = tls_intel._normalize_target(
        fingerprint,
        IndicatorType.TLS_CERTIFICATE.value,
    )

    assert result["fingerprint"] == "aa" * 32


def test_reject_invalid_fingerprint():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "invalid-fingerprint",
            IndicatorType.TLS_CERTIFICATE.value,
        )


def test_reject_short_fingerprint():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "a" * 63,
            IndicatorType.TLS_CERTIFICATE.value,
        )


# ---------------------------------------------------------
# DNS and public-address validation
# ---------------------------------------------------------

def test_resolve_public_addresses(monkeypatch):
    fake_answers = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("8.8.8.8", 0),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("1.1.1.1", 0),
        ),
    ]

    monkeypatch.setattr(
        tls_intel.socket,
        "getaddrinfo",
        lambda *args, **kwargs: fake_answers,
    )

    result = tls_intel._resolve_public_addresses("example.com")

    assert result == ["8.8.8.8", "1.1.1.1"]


def test_reject_dns_with_private_address(monkeypatch):
    fake_answers = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("8.8.8.8", 0),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("192.168.1.10", 0),
        ),
    ]

    monkeypatch.setattr(
        tls_intel.socket,
        "getaddrinfo",
        lambda *args, **kwargs: fake_answers,
    )

    with pytest.raises(ValueError):
        tls_intel._resolve_public_addresses("example.com")


def test_reject_excessive_dns_answers(monkeypatch):
    fake_answers = [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (f"8.8.8.{index}", 0),
        )
        for index in range(1, 22)
    ]

    monkeypatch.setattr(
        tls_intel.socket,
        "getaddrinfo",
        lambda *args, **kwargs: fake_answers,
    )

    with pytest.raises(RuntimeError):
        tls_intel._resolve_public_addresses("example.com")


def test_dns_resolution_failure(monkeypatch):
    def fail_dns(*args, **kwargs):
        raise socket.gaierror("DNS unavailable")

    monkeypatch.setattr(
        tls_intel.socket,
        "getaddrinfo",
        fail_dns,
    )

    with pytest.raises(RuntimeError):
        tls_intel._resolve_public_addresses("example.com")


# ---------------------------------------------------------
# TLS collector behaviour
# ---------------------------------------------------------

def test_successful_tls_collection(monkeypatch):
    monkeypatch.setattr(
        tls_intel,
        "_resolve_public_addresses",
        lambda hostname: ["8.8.8.8"],
    )

    monkeypatch.setattr(
        tls_intel,
        "_inspect_tls",
        lambda **kwargs: {
            "hostname": kwargs["hostname"],
            "connected_ip": kwargs["address"],
            "port": kwargs["port"],
            "tls_version": "TLSv1.3",
            "hostname_verification": "passed",
            "certificate_chain_verification": "passed",
        },
    )

    results = tls_intel.collect_tls_intel(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN.value,
    )

    assert len(results) == 1
    assert results[0].status == FindingStatus.SUCCESS
    assert results[0].finding["successful_inspections"][0][
        "tls_version"
    ] == "TLSv1.3"


def test_partial_tls_collection(monkeypatch):
    monkeypatch.setattr(
        tls_intel,
        "_resolve_public_addresses",
        lambda hostname: ["8.8.8.8", "1.1.1.1"],
    )

    def inspect(**kwargs):
        if kwargs["address"] == "1.1.1.1":
            raise OSError("Connection refused")

        return {
            "hostname": kwargs["hostname"],
            "connected_ip": kwargs["address"],
            "port": kwargs["port"],
        }

    monkeypatch.setattr(
        tls_intel,
        "_inspect_tls",
        inspect,
    )

    results = tls_intel.collect_tls_intel(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN.value,
    )

    assert len(results) == 1
    assert results[0].status == FindingStatus.PARTIAL
    assert len(
        results[0].finding["successful_inspections"]
    ) == 1
    assert len(results[0].finding["inspection_errors"]) == 1


def test_tls_connection_failure(monkeypatch):
    monkeypatch.setattr(
        tls_intel,
        "_resolve_public_addresses",
        lambda hostname: ["8.8.8.8"],
    )

    def fail_connection(**kwargs):
        raise OSError("Connection refused")

    monkeypatch.setattr(
        tls_intel,
        "_inspect_tls",
        fail_connection,
    )

    results = tls_intel.collect_tls_intel(
        indicator="example.com",
        indicator_type=IndicatorType.DOMAIN.value,
    )

    assert len(results) == 1
    assert results[0].status == FindingStatus.ERROR


def test_reject_private_ip_during_collection():
    results = tls_intel.collect_tls_intel(
        indicator="192.168.1.10",
        indicator_type=IndicatorType.IPV4.value,
    )

    assert len(results) == 1
    assert results[0].status == FindingStatus.ERROR


# ---------------------------------------------------------
# Passive certificate fingerprint lookup
# ---------------------------------------------------------

def test_fingerprint_lookup_without_token(monkeypatch):
    monkeypatch.delenv("CENSYS_API_TOKEN", raising=False)

    results = tls_intel.collect_tls_intel(
        indicator="a" * 64,
        indicator_type=IndicatorType.TLS_CERTIFICATE.value,
    )

    assert len(results) == 1
    assert results[0].status == FindingStatus.UNAVAILABLE


def test_successful_passive_fingerprint_lookup(monkeypatch):
    fingerprint = "a" * 64

    monkeypatch.setattr(
        tls_intel,
        "_lookup_censys_fingerprint",
        lambda value: {
            "fingerprint": fingerprint,
            "result": {"status": "found"},
        },
    )

    results = tls_intel.collect_tls_intel(
        indicator=fingerprint,
        indicator_type=IndicatorType.TLS_CERTIFICATE.value,
    )

    assert len(results) == 1
    assert results[0].status == FindingStatus.SUCCESS
    assert (
        results[0].finding["requested_sha256_fingerprint"]
        == fingerprint
    )


def test_reject_mismatched_censys_fingerprint(monkeypatch):
    monkeypatch.setattr(
        tls_intel,
        "_lookup_censys_fingerprint",
        lambda value: {
            "fingerprint": "b" * 64,
        },
    )

    results = tls_intel.collect_tls_intel(
        indicator="a" * 64,
        indicator_type=IndicatorType.TLS_CERTIFICATE.value,
    )

    assert len(results) == 1
    assert results[0].status == FindingStatus.ERROR


def test_censys_redirect_is_not_followed(monkeypatch):
    monkeypatch.setenv("CENSYS_API_TOKEN", "test-token")

    def redirect(*args, **kwargs):
        raise urllib.error.HTTPError(
            url="https://example.com",
            code=302,
            msg="Redirect",
            hdrs=Message(),
            fp=None,
        )

    class FakeOpener:
        def open(self, *args, **kwargs):
            return redirect()

    monkeypatch.setattr(
        tls_intel.urllib.request,
        "build_opener",
        lambda *args: FakeOpener(),
    )

    with pytest.raises(RuntimeError, match="redirect"):
        tls_intel._lookup_censys_fingerprint("a" * 64)
