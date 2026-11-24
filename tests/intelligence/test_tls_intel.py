
import pytest

from tracecase.contracts import (
    FindingStatus,
    IndicatorType,
)
from tracecase.intelligence import tls_intel


def test_normalizes_domain():
    host, kind, port, is_ip = tls_intel._normalize_target(
        "Example.COM",
        "domain",
    )

    assert host == "example.com"
    assert kind == IndicatorType.DOMAIN
    assert port == 443
    assert is_ip is False


def test_extracts_https_url_port():
    host, kind, port, is_ip = tls_intel._normalize_target(
        "https://example.com:8443/path",
        "url",
    )

    assert host == "example.com"
    assert kind == IndicatorType.URL
    assert port == 8443
    assert is_ip is False


def test_rejects_http_url():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "http://example.com",
            "url",
        )


def test_rejects_private_ip():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "192.168.1.10",
            "ipv4",
        )


def test_rejects_wrong_ip_version():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "2001:4860:4860::8888",
            "ipv4",
        )


def test_rejects_invalid_fingerprint():
    with pytest.raises(ValueError):
        tls_intel._normalize_target(
            "not-a-certificate-fingerprint",
            "tls_certificate",
        )


def test_fingerprint_uses_passive_lookup_only(monkeypatch):
    monkeypatch.delenv("CENSYS_API_TOKEN", raising=False)

    fingerprint = "a" * 64

    results = tls_intel.collect_tls_intel(
        indicator=fingerprint,
        indicator_type="tls_certificate",
    )

    assert len(results) == 1
    assert results[0].status == FindingStatus.UNAVAILABLE
    assert results[0].finding["lookup_mode"] == "passive"
    assert results[0].finding["provider_configured"] is False

def test_rejects_non_public_dns_answer(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                2,
                1,
                6,
                "",
                ("192.168.1.10", 443),
            )
        ]

    monkeypatch.setattr(
        tls_intel.socket,
        "getaddrinfo",
        fake_getaddrinfo,
    )

    with pytest.raises(ValueError):
        tls_intel._resolve_public_addresses(
            "example.com",
            443,
            False,
        )


def test_successful_tls_collection(monkeypatch):
    fake_result = {
        "host": "example.com",
        "connected_address": "93.184.216.34",
        "port": 443,
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "certificate": {
            "sha256_fingerprint": "a" * 64,
            "hostname_verification": "passed",
            "chain_verification": "passed",
        },
    }

    monkeypatch.setattr(
        tls_intel,
        "_resolve_public_addresses",
        lambda *args: ["93.184.216.34"],
    )

    monkeypatch.setattr(
        tls_intel,
        "_inspect_certificate",
        lambda **kwargs: fake_result,
    )

    results = tls_intel.collect_tls_intel(
        indicator="example.com",
        indicator_type="domain",
    )

    assert len(results) == 1
    assert results[0].status == FindingStatus.SUCCESS
    assert results[0].finding["certificate"]["sha256_fingerprint"] == "a" * 64
    assert results[0].source == "tls"


def test_tls_connection_failure_returns_error(monkeypatch):
    monkeypatch.setattr(
        tls_intel,
        "_resolve_public_addresses",
        lambda *args: ["93.184.216.34"],
    )

    def fake_inspection(**kwargs):
        raise OSError("simulated connection failure")

    monkeypatch.setattr(
        tls_intel,
        "_inspect_certificate",
        fake_inspection,
    )

    results = tls_intel.collect_tls_intel(
        indicator="example.com",
        indicator_type="domain",
    )

    assert len(results) == 1
    assert results[0].status == FindingStatus.ERROR
    assert results[0].finding["error_types"] == ["OSError"]


def test_dns_failure_returns_error(monkeypatch):
    def fake_resolution(*args):
        raise OSError("simulated DNS failure")

    monkeypatch.setattr(
        tls_intel,
        "_resolve_public_addresses",
        fake_resolution,
    )

    results = tls_intel.collect_tls_intel(
        indicator="example.com",
        indicator_type="domain",
    )

    assert len(results) == 1
    assert results[0].status == FindingStatus.ERROR

def test_normalizes_colon_separated_fingerprint():
    fingerprint = ":".join(["ab"] * 32)

    host, kind, port, is_ip = tls_intel._normalize_target(
        "SHA256:" + fingerprint,
        "tls_certificate",
    )

    assert host == "ab" * 32
    assert kind == IndicatorType.TLS_CERTIFICATE
    assert port == 443
    assert is_ip is False


def test_rejects_single_label_hostname():
    with pytest.raises(ValueError):
        tls_intel._normalize_target("localhost", "hostname")


def test_rejects_reserved_hostname_suffix():
    with pytest.raises(ValueError):
        tls_intel._normalize_target("server.internal", "hostname")


def test_rejects_excessive_dns_answers(monkeypatch):
    fake_answers = [
        (2, 1, 6, "", (f"8.8.8.{index}", 443))
        for index in range(1, 22)
    ]

    monkeypatch.setattr(
        tls_intel.socket,
        "getaddrinfo",
        lambda *args, **kwargs: fake_answers,
    )

    with pytest.raises(ValueError, match="too many DNS answers"):
        tls_intel._resolve_public_addresses("example.com", 443, False)


def test_partial_tls_collection_preserves_success_and_failure(monkeypatch):
    fake_result = {
        "host": "example.com",
        "connected_address": "93.184.216.34",
        "port": 443,
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "certificate": {
            "sha256_fingerprint": "a" * 64,
            "hostname_verification": "passed",
            "chain_verification": "passed",
        },
    }

    addresses = ["93.184.216.34", "1.1.1.1"]

    monkeypatch.setattr(
        tls_intel,
        "_resolve_public_addresses",
        lambda *args: addresses,
    )

    def fake_inspection(**kwargs):
        if kwargs["address"] == addresses[0]:
            return fake_result
        raise OSError("simulated second-address failure")

    monkeypatch.setattr(
        tls_intel,
        "_inspect_certificate",
        fake_inspection,
    )

    results = tls_intel.collect_tls_intel(
        indicator="example.com",
        indicator_type="domain",
    )

    assert len(results) == 1
    assert results[0].status == FindingStatus.PARTIAL
    assert results[0].finding["certificate"]["sha256_fingerprint"] == "a" * 64
    assert results[0].finding["successful_inspections"] == 1
    assert results[0].finding["resolved_addresses"] == addresses
    assert results[0].finding["inspection_errors"][0]["address"] == addresses[1]


def test_censys_redirect_handler_does_not_follow_redirects():
    handler = tls_intel._NoRedirectHandler()

    result = handler.redirect_request(
        None,
        None,
        302,
        "Found",
        {},
        "https://redirect.example/",
    )

    assert result is None
