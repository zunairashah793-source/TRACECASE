import json
from unittest.mock import Mock

import pytest
import requests

import tracecase.intelligence.ip_intel as ip_module


def test_rdap_parser_ignores_malformed_collections():
    result = ip_module._parse_ip_rdap({
        "cidr0_cidrs": "not-a-list",
        "events": None,
        "entities": {"unexpected": "object"},
        "status": "active",
    })
    assert result["cidrs"] == []
    assert result["events"] == []
    assert result["registrants"] == []
    assert result["status"] == []


def test_rdap_parser_rejects_boolean_and_invalid_cidr_lengths():
    result = ip_module._parse_ip_rdap({
        "cidr0_cidrs": [
            {"v4prefix": "8.8.8.0", "length": True},
            {"v4prefix": "8.8.8.0", "length": 33},
            {"v6prefix": "2001:4860::", "length": 64},
        ]
    })
    assert result["cidrs"] == [{"prefix": "2001:4860::", "length": 64}]


@pytest.mark.parametrize(
    "latitude,longitude,expected",
    [
        (37.5, -122.0, (37.5, -122.0)),
        (91, 0, (None, 0)),
        (0, -181, (0, None)),
        (True, 0, (None, 0)),
        (float("nan"), 0, (None, 0)),
        ("37.5", "0", (None, None)),
    ],
)
def test_geo_coordinates_are_validated(latitude, longitude, expected):
    parsed = ip_module._parse_ip_geo({
        "latitude": latitude,
        "longitude": longitude,
    })
    assert (parsed["latitude"], parsed["longitude"]) == expected


def test_fetch_ip_rdap_disables_redirects(monkeypatch):
    response = Mock()
    response.json.return_value = {"handle": "TEST"}
    get = Mock(return_value=response)
    monkeypatch.setattr(ip_module.requests, "get", get)

    assert ip_module._fetch_ip_rdap("8.8.8.8") == {"handle": "TEST"}
    assert get.call_args.kwargs["allow_redirects"] is False
    assert get.call_args.kwargs["stream"] is True


def test_request_json_rejects_redirect_response(monkeypatch):
    response = Mock()
    response.status_code = 302
    response.headers = {}
    get = Mock(return_value=response)
    monkeypatch.setattr(ip_module.requests, "get", get)

    with pytest.raises(ValueError, match="redirect"):
        ip_module._request_json("https://rdap.org/ip/8.8.8.8", (3.05, 10))


def test_request_json_rejects_oversized_content_length(monkeypatch):
    response = Mock()
    response.status_code = 200
    response.headers = {"Content-Length": str(ip_module.MAX_RESPONSE_BYTES + 1)}
    get = Mock(return_value=response)
    monkeypatch.setattr(ip_module.requests, "get", get)

    with pytest.raises(ValueError, match="size limit"):
        ip_module._request_json("https://rdap.org/ip/8.8.8.8", (3.05, 10))


def test_geo_fallback_records_actual_provider_url(monkeypatch):
    primary = Mock()
    primary.json.side_effect = ValueError("bad response")
    fallback = Mock()
    fallback.json.return_value = {
        "ip": "8.8.8.8",
        "city": "Example City",
        "country_name": "Example Country",
        "latitude": 10.0,
        "longitude": 20.0,
    }
    monkeypatch.setattr(
        ip_module.requests,
        "get",
        Mock(side_effect=[primary, fallback]),
    )

    result = ip_module._fetch_ip_geo("8.8.8.8")
    assert result["provider"] == "IPAPI"
    assert result["source_url"] == "https://ipapi.co/8.8.8.8/json/"


def test_failure_reason_does_not_expose_provider_exception_text():
    exc = requests.HTTPError("secret response body: token=do-not-leak")
    assert ip_module._safe_failure_reason(exc) == "provider returned an HTTP error"
    assert "secret" not in ip_module._safe_failure_reason(exc)


def test_collector_uses_lowercase_sources_and_canonical_timestamp(monkeypatch):
    monkeypatch.setattr(ip_module, "_fetch_ip_rdap", lambda ip: {})
    monkeypatch.setattr(ip_module, "_fetch_ip_asn", lambda ip: {})
    monkeypatch.setattr(
        ip_module,
        "_fetch_ip_geo",
        lambda ip: {
            "city": "Example",
            "provider": "IPAPI",
            "source_url": "https://ipapi.co/8.8.8.8/json/",
        },
    )

    results = ip_module.collect_ip_intel(
        indicator="8.8.8.8",
        indicator_type="ipv4",
    )

    assert [item.source for item in results] == ["rdap", "ipwhois", "geoip"]
    assert all(item.collected_at_utc.endswith("Z") for item in results)
    assert results[2].source_url == "https://ipapi.co/8.8.8.8/json/"


def test_source_failures_are_independent_and_sanitized(monkeypatch):
    monkeypatch.setattr(
        ip_module,
        "_fetch_ip_rdap",
        Mock(side_effect=RuntimeError("sensitive provider response")),
    )
    monkeypatch.setattr(ip_module, "_fetch_ip_asn", lambda ip: {})
    monkeypatch.setattr(
        ip_module,
        "_fetch_ip_geo",
        lambda ip: {"provider": "IPWHOIS", "source_url": "https://ipwho.is/8.8.8.8"},
    )

    results = ip_module.collect_ip_intel(
        indicator="8.8.8.8",
        indicator_type="ipv4",
    )
    assert results[0].status == ip_module.FindingStatus.UNAVAILABLE
    assert results[1].status == ip_module.FindingStatus.SUCCESS
    assert results[2].status == ip_module.FindingStatus.SUCCESS
    assert "sensitive" not in " ".join(results[0].limitations)
