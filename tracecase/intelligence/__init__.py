from ..contracts import FindingPayload, IndicatorType, TargetKind
from . import domain_intel, ip_intel, reputation, tls_intel


def collect_external_intelligence(
    *,
    indicator: str,
    indicator_type: str,
    target_kind: str,
) -> list[FindingPayload]:
    """Collect passive intelligence for an explicitly public target."""

    if not isinstance(indicator, str) or not indicator.strip():
        raise ValueError("A non-empty indicator is required.")

    try:
        kind = IndicatorType(indicator_type)
        scope = TargetKind(target_kind)
    except (ValueError, TypeError):
        raise ValueError("Unsupported indicator or target kind.") from None

    if scope != TargetKind.EXTERNAL_PUBLIC:
        raise ValueError(
            "External intelligence is restricted to external_public targets."
        )

    value = indicator.strip()
    results: list[FindingPayload] = []

    if kind in (IndicatorType.IPV4, IndicatorType.IPV6):
        results.extend(ip_intel.collect_ip_intel(
            indicator=value, indicator_type=kind.value
        ))
        results.extend(reputation.collect_reputation(
            indicator=value, indicator_type=kind.value
        ))
        results.extend(tls_intel.collect_tls_intel(
            indicator=value, indicator_type=kind.value
        ))

    elif kind in (
        IndicatorType.DOMAIN,
        IndicatorType.SUBDOMAIN,
        IndicatorType.HOSTNAME,
        IndicatorType.URL,
    ):
        results.extend(domain_intel.collect_domain_intel(
            indicator=value, indicator_type=kind.value
        ))
        results.extend(tls_intel.collect_tls_intel(
            indicator=value, indicator_type=kind.value
        ))

    elif kind == IndicatorType.TLS_CERTIFICATE:
        results.extend(tls_intel.collect_tls_intel(
            indicator=value, indicator_type=kind.value
        ))

    return results
