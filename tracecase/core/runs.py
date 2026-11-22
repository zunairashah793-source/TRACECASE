create_run(data: RunCreate) -> InvestigationRun

update_run_status(
    run_id: str,
    status: str,
    *,
    summary: str | None = None,
    error_summary: str | None = None
) -> InvestigationRun

get_run(case_id: str, run_id: str) -> InvestigationRun | None

list_runs(
    case_id: str,
    target_id: str | None = None
) -> list[InvestigationRun]