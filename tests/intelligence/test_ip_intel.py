from unittest.mock import Mock

import requests

import tracecase.intelligence.ip_intel as ip_module

import pytest

from tracecase.intelligence.ip_intel import _normalize_public_ip


@pytest.mark.parametrize(
    "indicator",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "::ffff:8.8.8.8",
    ],
)
def test_accepts_public_global_ips(indicator):
    result = _normalize_public_ip(indicator)

    assert result
    assert isinstance(result, str)


@pytest.mark.parametrize(
    "indicator",
    [
        "192.168.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "240.0.0.1",
        "100.64.0.1",
        "2001:db8::1",
        "fe80::1",
        "fc00::1",
        "::1",
        "ff02::1",
        "::ffff:192.168.1.1",
        "64:ff9b::808:808",
    ],
)
def test_rejects_non_public_ips(indicator):
    with pytest.raises(ValueError):
        _normalize_public_ip(indicator)


@pytest.mark.parametrize(
    "indicator",
    [
        "",
        "google.com",
        "not-an-ip",
        "999.999.999.999",
    ],
)
def test_rejects_invalid_indicators(indicator):
    with pytest.raises(ValueError):
        _normalize_public_ip(indicator)

def test_fetch_ip_rdap_returns_record(monkeypatch):
    expected_record = {
        "objectClassName": "ip network",
        "handle": "TEST-NETWORK",
        "startAddress": "8.8.8.0",
        "endAddress": "8.8.8.255",
    }

    mock_response = Mock()
    mock_response.json.return_value = expected_record

    mock_get = Mock(return_value=mock_response)
    monkeypatch.setattr(ip_module.requests, "get", mock_get)

    result = ip_module._fetch_ip_rdap("8.8.8.8")

    assert result == expected_record
    mock_get.assert_called_once()

    args, kwargs = mock_get.call_args
    assert args[0] == "https://rdap.org/ip/8.8.8.8"
    assert kwargs["timeout"] == (3.05, 10)
    assert kwargs["allow_redirects"] is False


def test_fetch_ip_rdap_rejects_private_ip_without_request(monkeypatch):
    mock_get = Mock()
    monkeypatch.setattr(ip_module.requests, "get", mock_get)

    with pytest.raises(ValueError):
        ip_module._fetch_ip_rdap("192.168.1.1")

    mock_get.assert_not_called()


def test_fetch_ip_rdap_propagates_http_error(monkeypatch):
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = requests.HTTPError(
        "RDAP request failed"
    )

    monkeypatch.setattr(
        ip_module.requests,
        "get",
        Mock(return_value=mock_response),
    )

    with pytest.raises(requests.HTTPError):
        ip_module._fetch_ip_rdap("8.8.8.8")


def test_fetch_ip_rdap_rejects_non_object_response(monkeypatch):
    mock_response = Mock()
    mock_response.json.return_value = ["unexpected", "data"]

    monkeypatch.setattr(
        ip_module.requests,
        "get",
        Mock(return_value=mock_response),
    )

    with pytest.raises(ValueError):
        ip_module._fetch_ip_rdap("8.8.8.8")


def test_fetch_ip_rdap_rejects_invalid_json(monkeypatch):
    mock_response = Mock()
    mock_response.json.side_effect = ValueError("Invalid JSON")

    monkeypatch.setattr(
        ip_module.requests,
        "get",
        Mock(return_value=mock_response),
    )

    with pytest.raises(ValueError, match="[Ii]nvalid JSON"):
        ip_module._fetch_ip_rdap("8.8.8.8")

def test_parse_ip_rdap_extracts_registration_metadata():
    record = {
        "name": "GOGL",
        "handle": "NET-8-8-8-0-2",
        "type": "DIRECT ALLOCATION",
        "startAddress": "8.8.8.0",
        "endAddress": "8.8.8.255",
        "ipVersion": "v4",
        "cidr0_cidrs": [
            {"v4prefix": "8.8.8.0", "length": 24}
        ],
        "status": ["active"],
        "entities": [
            {
                "handle": "GOGL",
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Google LLC"]],
                ],
            },
        ],
    }

    result = ip_module._parse_ip_rdap(record)

    assert result["name"] == "GOGL"
    assert result["handle"] == "NET-8-8-8-0-2"
    assert result["cidrs"] == [
        {"prefix": "8.8.8.0", "length": 24}
    ]
    assert result["registrants"] == [
        {"handle": "GOGL", "name": "Google LLC"}
    ]


def test_parse_ip_rdap_handles_missing_fields():
    result = ip_module._parse_ip_rdap({})

    assert result["name"] is None
    assert result["country"] is None
    assert result["cidrs"] == []
    assert result["events"] == []
    assert result["registrants"] == []


def test_parse_ip_rdap_does_not_extract_contact_details():
    record = {
        "entities": [
            {
                "handle": "GOGL",
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [
                        ["fn", {}, "text", "Google LLC"],
                        ["email", {}, "text", "example@example.com"],
                        ["tel", {}, "text", "+123456789"],
                    ],
                ],
            },
        ],
    }

    result = ip_module._parse_ip_rdap(record)

    assert result["registrants"] == [
        {"handle": "GOGL", "name": "Google LLC"}
    ]
    assert "email" not in str(result)
    assert "tel" not in str(result)


def test_parse_ip_rdap_rejects_invalid_record():
    with pytest.raises(ValueError):
        ip_module._parse_ip_rdap(None)  # type: ignore[arg-type]

def test_fetch_ip_asn_success(monkeypatch):
    from tracecase.intelligence import ip_intel

    payload = {
        "success": True,
        "ip": "8.8.8.8",
        "connection": {
            "asn": 15169,
            "org": "Google LLC",
            "isp": "Google LLC",
            "domain": "google.com",
        },
    }

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return payload

    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return FakeResponse()

    monkeypatch.setattr(ip_intel.requests, "get", fake_get)

    result = ip_intel._fetch_ip_asn("8.8.8.8")

    assert result == payload
    assert captured["url"] == "https://ipwho.is/8.8.8.8"
    assert captured["kwargs"]["timeout"] == ip_intel.IPWHOIS_TIMEOUT


def test_fetch_ip_asn_rejects_private_ip(monkeypatch):
    import pytest
    from tracecase.intelligence import ip_intel

    def unexpected_request(*args, **kwargs):
        raise AssertionError("Provider must not be called")

    monkeypatch.setattr(ip_intel.requests, "get", unexpected_request)

    with pytest.raises(ValueError):
        ip_intel._fetch_ip_asn("192.168.1.1")


def test_fetch_ip_asn_rejects_provider_failure(monkeypatch):
    import pytest
    from tracecase.intelligence import ip_intel

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"success": False, "message": "Invalid IP"}

    monkeypatch.setattr(
        ip_intel.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(),
    )

    with pytest.raises(ValueError):
        ip_intel._fetch_ip_asn("8.8.8.8")


def test_fetch_ip_asn_rejects_mismatched_ip(monkeypatch):
    import pytest
    from tracecase.intelligence import ip_intel

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "success": True,
                "ip": "1.1.1.1",
                "connection": {},
            }

    monkeypatch.setattr(
        ip_intel.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(),
    )

    with pytest.raises(ValueError):
        ip_intel._fetch_ip_asn("8.8.8.8")


def test_parse_ip_asn_extracts_connection_details():
    from tracecase.intelligence import ip_intel

    result = ip_intel._parse_ip_asn({
        "connection": {
            "asn": 15169,
            "org": "Google LLC",
            "isp": "Google LLC",
            "domain": "google.com",
        }
    })

    assert result == {
        "asn": 15169,
        "organisation": "Google LLC",
        "isp": "Google LLC",
        "domain": "google.com",
    }


def test_parse_ip_asn_handles_missing_connection():
    from tracecase.intelligence import ip_intel

    result = ip_intel._parse_ip_asn({})

    assert result == {
        "asn": None,
        "organisation": None,
        "isp": None,
        "domain": None,
    }


def test_parse_ip_asn_rejects_boolean_asn():
    from tracecase.intelligence import ip_intel

    result = ip_intel._parse_ip_asn({
        "connection": {"asn": True}
    })

    assert result["asn"] is None

def test_parse_ip_asn_extracts_asn_and_isp():
    record = {
        "connection": {
            "asn": 15169,
            "org": "Google LLC",
            "isp": "Google LLC",
            "domain": "google.com",
        }
    }

    result = ip_module._parse_ip_asn(record)

    assert result == {
        "asn": 15169,
        "organisation": "Google LLC",
        "isp": "Google LLC",
        "domain": "google.com",
    }



def test_parse_ip_asn_rejects_invalid_record():
    with pytest.raises(ValueError):
        ip_module._parse_ip_asn(None)  # type: ignore[arg-type]



def test_fetch_ip_geo_uses_ipapi_when_ipwhois_fails(monkeypatch):
    ipapi_payload = {
        "ip": "8.8.8.8",
        "city": "San Jose",
        "region": "California",
        "country_name": "United States",
        "country_code": "US",
        "latitude": 37.3393939,
        "longitude": -121.8949553,
        "timezone": "America/Los_Angeles",
        "org": "Google LLC",
    }

    primary_response = Mock()
    primary_response.raise_for_status.side_effect = requests.HTTPError(
        "IPWHOIS temporarily unavailable"
    )

    fallback_response = Mock()
    fallback_response.raise_for_status.return_value = None
    fallback_response.json.return_value = ipapi_payload

    mock_get = Mock(
        side_effect=[primary_response, fallback_response]
    )

    monkeypatch.setattr(ip_module.requests, "get", mock_get)

    # Fetch using the fallback provider.
    result = ip_module._fetch_ip_geo("8.8.8.8")

    # Verify the normalized provider response.
    assert result["city"] == "San Jose"
    assert result["region"] == "California"
    assert result["country_name"] == "United States"
    assert result["country_code"] == "US"
    assert result["latitude"] == 37.3393939
    assert result["provider"] == "IPAPI"

    # Verify that the IPAPI request was actually made.
    assert mock_get.call_count == 2
    assert "ipwho.is" in mock_get.call_args_list[0].args[0]
    assert "ipapi.co" in mock_get.call_args_list[1].args[0]

    # Verify conversion into the final application format.
    parsed = ip_module._parse_ip_geo(result)

    assert parsed["country"] == "United States"
    assert parsed["geo_provider"] == "IPAPI"
    assert parsed["location_type"] == "Approximate IP-based location"
