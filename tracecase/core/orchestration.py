run_external_investigation(
    *,
    case_id: str,
    target_id: str
) -> OperationSummary

import_network_artifact(
    *,
    case_id: str,
    target_id: str,
    uploaded_file,
    artifact_type: str,
    source_tool: str,
    notes: str | None = None
) -> OperationSummary

run_assessment_job(
    *,
    case_id: str,
    target_id: str,
    execution_mode: str,
    operation: str,
    profile_id: str,
    authorization_confirmed: bool
) -> OperationSummary

import_case_evidence(
    *,
    case_id: str,
    uploaded_file,
    evidence_type: str,
    source_tool: str,
    notes: str | None = None
) -> Evidence