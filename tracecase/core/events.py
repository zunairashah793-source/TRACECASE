append_case_event(data: CaseEventCreate) -> CaseEvent

list_case_events(
    case_id: str,
    target_id: str | None = None
) -> list[CaseEvent]