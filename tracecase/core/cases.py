create_case(data: CaseCreate) -> Case

get_case(case_id: str) -> Case | None

list_cases(filters: CaseFilters | None = None) -> list[Case]

update_case(data: CaseUpdate) -> Case

close_case(case_id: str) -> Case