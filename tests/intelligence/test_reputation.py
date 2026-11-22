import io
import os
from unittest.mock import Mock

import pytest
import requests

import tracecase.intelligence.reputation as reputation


def _valid_response_data(ip="8.8.8.8"):
    return {
        "ipAddress": ip,
        "abuseConfidenceScore": 25,
        "totalReports": 12,
        "numDistinctUsers": 8,
        "lastReportedAt": "2026-11-20T12:00:00+00:00",
        "countryCode": "US",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example ISP",
        "domain": "example.com",
        "isWhitelisted": False,
    }


def _mock_response(data, status_code=200):
    response = Mock()
    response.status_code = status_code
    response.headers = {}
    response.json.return_value = {"data": data}
    return response


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("8.8.8.8", "8.8.8.8"),
        ("1.1.1.1", "1.1.1.1"),
        ("2606:4700:4700::1111", "2606:4700:4700::1111"),
    ],
)
def test_normalize_public_ip_accepts_global_addresses(ip, expected):
    assert reputation._normalize_public_ip(ip) == expected


@pytest.mark.parametrize(
    "ip",
    [
        "",
        "not-an-ip",
        "192.168.1.1",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
    ],
)
def test_normalize_public_ip_rejects_invalid_or_non_global_addresses(ip):
    with pytest.raises(ValueError):
        reputation._normalize_public_ip(ip)


def test_collector_rejects_invalid_ip_without_network_request(monkeypatch):
    get = Mock()
    monkeypatch.setattr(reputation.requests, "get", get)

    with pytest.raises(ValueError):
        reputation.collect_reputation(
            indicator="192.168.1.10",
            indicator_type="ipv4",
        )

    get.assert_not_called()


def test_collector_rejects_indicator_type_mismatch(monkeypatch):
    get = Mock()
    monkeypatch.setattr(reputation.requests, "get", get)

    with pytest.raises(ValueError, match="does not match"):
        reputation.collect_reputation(
            indicator="8.8.8.8",
            indicator_type="ipv6",
        )

    get.assert_not_called()


def test_missing_api_key_returns_unavailable_without_request(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    get = Mock()
    monkeypatch.setattr(reputation.requests, "get", get)

    results = reputation.collect_reputation(
        indicator="8.8.8.8",
        indicator_type="ipv4",
    )

    assert len(results) == 1
    assert results[0].status == reputation.FindingStatus.UNAVAILABLE
    assert results[0].source == "abuseipdb"
    assert "No reputation conclusion" in " ".join(results[0].limitations)
    assert results[0].finding == {}
    get.assert_not_called()


def test_request_uses_expected_endpoint_headers_and_parameters(monkeypatch):
    response = _mock_response(_valid_response_data())
    get = Mock(return_value=response)
    monkeypatch.setattr(reputation.requests, "get", get)

    result = reputation._request_abuseipdb("8.8.8.8", "test-secret-key")

    assert result["ipAddress"] == "8.8.8.8"
    args, kwargs = get.call_args

    assert args[0] == reputation.API_URL
    assert kwargs["headers"]["Key"] == "test-secret-key"
    assert kwargs["headers"]["Accept"] == "application/json"
    assert kwargs["params"] == {
        "ipAddress": "8.8.8.8",
        "maxAgeInDays": reputation.DEFAULT_MAX_AGE_DAYS,
    }
    assert kwargs["timeout"] == reputation.TIMEOUT
    assert kwargs["allow_redirects"] is False
    assert kwargs["stream"] is True
    response.close.assert_called_once()


def test_request_rejects_redirect_response(monkeypatch):
    response = _mock_response(_valid_response_data(), status_code=302)
    get = Mock(return_value=response)
    monkeypatch.setattr(reputation.requests, "get", get)

    with pytest.raises(ValueError, match="redirect"):
        reputation._request_abuseipdb("8.8.8.8", "test-key")


def test_request_rejects_oversized_content_length(monkeypatch):
    response = _mock_response(_valid_response_data())
    response.headers = {
        "Content-Length": str(reputation.MAX_RESPONSE_BYTES + 1)
    }
    get = Mock(return_value=response)
    monkeypatch.setattr(reputation.requests, "get", get)

    with pytest.raises(ValueError, match="size limit"):
        reputation._request_abuseipdb("8.8.8.8", "test-key")


def test_parser_rejects_missing_or_invalid_returned_ip():
    with pytest.raises(ValueError, match="did not return an IP"):
        reputation._parse_reputation(
            {"abuseConfidenceScore": 0},
            "8.8.8.8",
        )


def test_parser_rejects_different_returned_ip():
    with pytest.raises(ValueError, match="different IP"):
        reputation._parse_reputation(
            _valid_response_data("1.1.1.1"),
            "8.8.8.8",
        )


@pytest.mark.parametrize("score", [-1, 101, True, "25", None])
def test_parser_rejects_invalid_abuse_confidence_score(score):
    data = _valid_response_data()
    data["abuseConfidenceScore"] = score

    with pytest.raises(ValueError, match="confidence score"):
        reputation._parse_reputation(data, "8.8.8.8")


def test_parser_ignores_malformed_optional_fields():
    data = _valid_response_data()
    data.update({
        "totalReports": True,
        "numDistinctUsers": -1,
        "lastReportedAt": 123,
        "countryCode": [],
        "isWhitelisted": "false",
    })

    result = reputation._parse_reputation(data, "8.8.8.8")

    assert result["total_reports"] is None
    assert result["distinct_reporters"] is None
    assert result["last_reported_at"] is None
    assert result["country_code"] is None
    assert result["is_whitelisted"] is None


def test_successful_collection_returns_contract_payload(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-secret-key")
    monkeypatch.setattr(
        reputation,
        "_request_abuseipdb",
        lambda ip, key: _valid_response_data(ip),
    )

    results = reputation.collect_reputation(
        indicator="8.8.8.8",
        indicator_type="ipv4",
    )

    assert len(results) == 1
    result = results[0]

    assert isinstance(result, reputation.FindingPayload)
    assert result.indicator == "8.8.8.8"
    assert result.indicator_type == reputation.IndicatorType.IPV4
    assert result.category == reputation.FindingCategory.EXTERNAL_INTELLIGENCE
    assert result.source == "abuseipdb"
    assert result.status == reputation.FindingStatus.SUCCESS
    assert result.confidence == reputation.Confidence.MEDIUM
    assert result.finding["abuse_confidence_score"] == 25
    assert result.finding["total_reports"] == 12
    assert result.finding["distinct_reporters"] == 8
    assert result.finding["reporting_period_days"] == 90
    assert result.collected_at_utc.endswith("Z")
    assert result.source_url == reputation.API_URL
    assert "does not prove" in " ".join(result.limitations)


def test_provider_request_failure_returns_unavailable_without_secrets(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-secret-key")
    monkeypatch.setattr(
        reputation,
        "_request_abuseipdb",
        Mock(side_effect=requests.Timeout("secret provider response")),
    )

    results = reputation.collect_reputation(
        indicator="8.8.8.8",
        indicator_type="ipv4",
    )

    assert results[0].status == reputation.FindingStatus.UNAVAILABLE
    assert results[0].finding == {}
    combined = " ".join(results[0].limitations) + results[0].summary
    assert "secret" not in combined
    assert "test-secret-key" not in combined


def test_invalid_provider_response_returns_error_without_api_key(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-secret-key")
    monkeypatch.setattr(
        reputation,
        "_request_abuseipdb",
        lambda ip, key: {"ipAddress": "1.1.1.1"},
    )

    results = reputation.collect_reputation(
        indicator="8.8.8.8",
        indicator_type="ipv4",
    )

    assert results[0].status == reputation.FindingStatus.ERROR
    assert results[0].finding == {}
    combined = " ".join(results[0].limitations) + results[0].summary
    assert "test-secret-key" not in combined


def test_ipv6_collection_uses_ipv6_indicator_type(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-secret-key")
    ip = "2606:4700:4700::1111"
    monkeypatch.setattr(
        reputation,
        "_request_abuseipdb",
        lambda requested_ip, key: _valid_response_data(requested_ip),
    )

    results = reputation.collect_reputation(
        indicator=ip,
        indicator_type="ipv6",
    )

    assert results[0].indicator == ip
    assert results[0].indicator_type == reputation.IndicatorType.IPV6
    assert results[0].status == reputation.FindingStatus.SUCCESS

def _real_streaming_response(body):
    response = requests.Response()
    response.status_code = 200
    response.encoding = "utf-8"
    response.raw = io.BytesIO(body)
    response._content_consumed = False

    close_mock = Mock(wraps=response.close)
    setattr(response, "close", close_mock)

    return response, close_mock


def test_real_requests_response_uses_bounded_streaming(monkeypatch):
    import json

    body = json.dumps({"data": _valid_response_data()}).encode("utf-8")
    response, close_mock = _real_streaming_response(body)
    monkeypatch.setattr(
        reputation.requests,
        "get",
        Mock(return_value=response),
    )

    result = reputation._request_abuseipdb("8.8.8.8", "test-key")

    assert result["ipAddress"] == "8.8.8.8"
    close_mock.assert_called_once()


def test_real_requests_response_rejects_oversized_stream(monkeypatch):
    body = b"x" * (reputation.MAX_RESPONSE_BYTES + 1)
    response, close_mock = _real_streaming_response(body)
    monkeypatch.setattr(
        reputation.requests,
        "get",
        Mock(return_value=response),
    )

    with pytest.raises(ValueError, match="size limit"):
        reputation._request_abuseipdb("8.8.8.8", "test-key")

    close_mock.assert_called_once()
