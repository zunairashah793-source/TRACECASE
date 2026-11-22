validate_finding(
    payload: FindingPayload,
    *,
    target: Target
) -> ValidatedFinding

save_findings(
    *,
    case_id: str,
    target_id: str,
    run_id: str,
    findings: list[FindingPayload],
    primary_evidence_reference: str | None = None
) -> list[Finding]

list_findings(
    case_id: str,
    target_id: str | None = None,
    filters: FindingFilters | None = None
) -> list[Finding]

get_finding(
    case_id: str,
    finding_id: str
) -> Finding | None

add_manual_observation(
    *,
    case_id: str,
    target_id: str,
    summary: str,
    details: str,
    confidence: str,
    limitations: list[str]
) -> OperationSummary