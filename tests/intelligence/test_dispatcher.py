from unittest.mock import Mock

import pytest

import tracecase.intelligence as dispatcher


def test_public_ipv4_dispatches_to_ip_reputation_and_tls(monkeypatch):
    ip = Mock(return_value=["ip-result"])
    reputation = Mock(return_value=["reputation-result"])
    tls = Mock(return_value=["tls-result"])

    monkeypatch.setattr(dispatcher.ip_intel, "collect_ip_intel", ip)
    monkeypatch.setattr(
        dispatcher.reputation, "collect_reputation", reputation
    )
    monkeypatch.setattr(dispatcher.tls_intel, "collect_tls_intel", tls)

    results = dispatcher.collect_external_intelligence(
        indicator="8.8.8.8",
        indicator_type="ipv4",
        target_kind="external_public",
    )

    assert results == [
        "ip-result",
        "reputation-result",
        "tls-result",
    ]

    ip.assert_called_once_with(
        indicator="8.8.8.8",
        indicator_type="ipv4",
    )
    reputation.assert_called_once_with(
        indicator="8.8.8.8",
        indicator_type="ipv4",
    )
    tls.assert_called_once_with(
        indicator="8.8.8.8",
        indicator_type="ipv4",
    )


def test_public_domain_does_not_dispatch_to_ip_reputation(monkeypatch):
    domain = Mock(return_value=["domain-result"])
    reputation = Mock()
    tls = Mock(return_value=["tls-result"])

    monkeypatch.setattr(
        dispatcher.domain_intel, "collect_domain_intel", domain
    )
    monkeypatch.setattr(
        dispatcher.reputation, "collect_reputation", reputation
    )
    monkeypatch.setattr(dispatcher.tls_intel, "collect_tls_intel", tls)

    results = dispatcher.collect_external_intelligence(
        indicator="example.com",
        indicator_type="domain",
        target_kind="external_public",
    )

    assert results == ["domain-result", "tls-result"]
    domain.assert_called_once_with(
        indicator="example.com",
        indicator_type="domain",
    )
    reputation.assert_not_called()


def test_authorized_lab_scope_is_rejected_before_collection(monkeypatch):
    ip = Mock()
    reputation = Mock()
    tls = Mock()

    monkeypatch.setattr(dispatcher.ip_intel, "collect_ip_intel", ip)
    monkeypatch.setattr(
        dispatcher.reputation, "collect_reputation", reputation
    )
    monkeypatch.setattr(dispatcher.tls_intel, "collect_tls_intel", tls)

    with pytest.raises(ValueError, match="external_public"):
        dispatcher.collect_external_intelligence(
            indicator="8.8.8.8",
            indicator_type="ipv4",
            target_kind="authorized_lab",
        )

    ip.assert_not_called()
    reputation.assert_not_called()
    tls.assert_not_called()


def test_unsupported_indicator_type_is_rejected():
    with pytest.raises(ValueError, match="Unsupported"):
        dispatcher.collect_external_intelligence(
            indicator="8.8.8.8",
            indicator_type="unsupported",
            target_kind="external_public",
        )


@pytest.mark.parametrize(
    "indicator, indicator_type",
    [
        ("2001:4860:4860::8888", "ipv6"),
    ],
)
def test_public_ipv6_dispatches_to_all_ip_collectors(
    monkeypatch, indicator, indicator_type
):
    ip = Mock(return_value=["ip-result"])
    reputation = Mock(return_value=["reputation-result"])
    tls = Mock(return_value=["tls-result"])

    monkeypatch.setattr(dispatcher.ip_intel, "collect_ip_intel", ip)
    monkeypatch.setattr(dispatcher.reputation, "collect_reputation", reputation)
    monkeypatch.setattr(dispatcher.tls_intel, "collect_tls_intel", tls)

    results = dispatcher.collect_external_intelligence(
        indicator=indicator,
        indicator_type=indicator_type,
        target_kind="external_public",
    )

    assert results == ["ip-result", "reputation-result", "tls-result"]
    ip.assert_called_once_with(
        indicator=indicator, indicator_type=indicator_type
    )
    reputation.assert_called_once_with(
        indicator=indicator, indicator_type=indicator_type
    )
    tls.assert_called_once_with(
        indicator=indicator, indicator_type=indicator_type
    )


@pytest.mark.parametrize(
    "indicator, indicator_type",
    [
        ("sub.example.com", "subdomain"),
        ("mail.example.com", "hostname"),
        ("https://example.com", "url"),
    ],
)
def test_domain_variants_dispatch_to_domain_and_tls(
    monkeypatch, indicator, indicator_type
):
    domain = Mock(return_value=["domain-result"])
    tls = Mock(return_value=["tls-result"])
    reputation = Mock()

    monkeypatch.setattr(
        dispatcher.domain_intel, "collect_domain_intel", domain
    )
    monkeypatch.setattr(dispatcher.tls_intel, "collect_tls_intel", tls)
    monkeypatch.setattr(
        dispatcher.reputation, "collect_reputation", reputation
    )

    results = dispatcher.collect_external_intelligence(
        indicator=indicator,
        indicator_type=indicator_type,
        target_kind="external_public",
    )

    assert results == ["domain-result", "tls-result"]
    domain.assert_called_once_with(
        indicator=indicator, indicator_type=indicator_type
    )
    tls.assert_called_once_with(
        indicator=indicator, indicator_type=indicator_type
    )
    reputation.assert_not_called()


def test_tls_certificate_dispatches_only_to_tls(monkeypatch):
    tls = Mock(return_value=["tls-result"])
    ip = Mock()
    domain = Mock()
    reputation = Mock()

    monkeypatch.setattr(dispatcher.tls_intel, "collect_tls_intel", tls)
    monkeypatch.setattr(dispatcher.ip_intel, "collect_ip_intel", ip)
    monkeypatch.setattr(
        dispatcher.domain_intel, "collect_domain_intel", domain
    )
    monkeypatch.setattr(
        dispatcher.reputation, "collect_reputation", reputation
    )

    results = dispatcher.collect_external_intelligence(
        indicator="a" * 64,
        indicator_type="tls_certificate",
        target_kind="external_public",
    )

    assert results == ["tls-result"]
    tls.assert_called_once()
    ip.assert_not_called()
    domain.assert_not_called()
    reputation.assert_not_called()
