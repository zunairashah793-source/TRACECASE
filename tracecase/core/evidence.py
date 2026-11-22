save_evidence_file(
    *,
    case_id: str,
    target_id: str | None,
    run_id: str,
    uploaded_file,
    evidence_type: str,
    source_tool: str,
    notes: str | None = None
) -> Evidence

verify_evidence(
    case_id: str,
    evidence_reference: str
) -> Evidence

list_evidence(
    case_id: str,
    target_id: str | None = None
) -> list[Evidence]

get_evidence_path(
    case_id: str,
    evidence_reference: str
) -> Path | None