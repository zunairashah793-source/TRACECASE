
import pytest

from tracecase.contracts import (
    Confidence,
    FindingCategory,
    FindingStatus,
    IndicatorType,
)

import tracecase.intelligence.domain_intel as domain_module


def test_normalize_domain_lowercases():
    assert domain_module._normalize_domain(
        "Example.COM",
        "domain",
    ) == "example.com"


def test_normalize_domain_supports_idna():
    result = domain_module._normalize_domain(
        "münich.com",
        "domain",
    )
    assert result == "xn--mnich-kva.com"


def test_normalize_domain_extracts_url_hostname():
    result = domain_module._normalize_domain(
        "https://Example.com/path?q=1",
        "url",
    )
    assert result == "example.com"


@pytest.mark.parametrize(
    "indicator, indicator_type",
    [
        ("127.0.0.1", "domain"),
        ("localhost", "hostname"),
        ("machine.local", "hostname"),
        ("example.com", "ipv4"),
        ("ftp://example.com", "url"),
        ("https://user:pass@example.com", "url"),
    ],
)
def test_rejects_unsupported_indicators(indicator, indicator_type):
    with pytest.raises(ValueError):
        domain_module._normalize_domain(indicator, indicator_type)


def test_successful_domain_finding(monkeypatch):
    records = {
        "A": ["93.184.216.34"],
        "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
        "MX": ["10 mail.example.com."],
        "NS": ["ns1.example.com."],
        "TXT": ["v=spf1 -all"],
    }

    outcomes = {
        record_type: "success"
        for record_type in domain_module.DNS_RECORD_TYPES
    }

    monkeypatch.setattr(
        domain_module,
        "_query_dns",
        lambda name: (records, outcomes, []),
    )

    result = domain_module.collect_domain_intel(
        indicator="example.com",
        indicator_type="domain",
    )

    assert len(result) == 1

    finding = result[0]

    assert finding.indicator == "example.com"
    assert finding.indicator_type == IndicatorType.DOMAIN
    assert finding.category == FindingCategory.EXTERNAL_INTELLIGENCE
    assert finding.source == "dns"
    assert finding.status == FindingStatus.SUCCESS
    assert finding.confidence == Confidence.MEDIUM
    assert finding.finding["queried_domain"] == "example.com"
    assert finding.finding["records"]["A"] == ["93.184.216.34"]
    assert finding.limitations == []


def test_partial_dns_result(monkeypatch):
    records = {
        "A": ["93.184.216.34"],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
    }

    outcomes = {
        "A": "success",
        "AAAA": "unavailable",
        "MX": "success",
        "NS": "success",
        "TXT": "success",
    }

    monkeypatch.setattr(
        domain_module,
        "_query_dns",
        lambda name: (
            records,
            outcomes,
            ["AAAA lookup timed out."],
        ),
    )

    result = domain_module.collect_domain_intel(
        indicator="example.com",
        indicator_type="domain",
    )

    assert result[0].status == FindingStatus.PARTIAL
    assert "AAAA lookup timed out." in result[0].limitations


def test_unavailable_dns_result(monkeypatch):
    records = {
        record_type: []
        for record_type in domain_module.DNS_RECORD_TYPES
    }

    outcomes = {
        record_type: "unavailable"
        for record_type in domain_module.DNS_RECORD_TYPES
    }

    monkeypatch.setattr(
        domain_module,
        "_query_dns",
        lambda name: (
            records,
            outcomes,
            ["DNS resolver unavailable."],
        ),
    )

    result = domain_module.collect_domain_intel(
        indicator="example.com",
        indicator_type="domain",
    )

    assert result[0].status == FindingStatus.UNAVAILABLE
    assert result[0].confidence == Confidence.UNKNOWN
    assert result[0].limitations == ["DNS resolver unavailable."]


def test_finding_timestamp_is_utc(monkeypatch):
    records = {
        record_type: []
        for record_type in domain_module.DNS_RECORD_TYPES
    }

    outcomes = {
        record_type: "no_answer"
        for record_type in domain_module.DNS_RECORD_TYPES
    }

    monkeypatch.setattr(
        domain_module,
        "_query_dns",
        lambda name: (records, outcomes, []),
    )

    result = domain_module.collect_domain_intel(
        indicator="example.com",
        indicator_type="domain",
    )

    timestamp = result[0].collected_at_utc

    assert timestamp.endswith("Z")
    assert len(timestamp) == 20
