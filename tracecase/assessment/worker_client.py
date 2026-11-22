select_worker(
    *,
    target_id: str,
    execution_mode: str
) -> WorkerDescriptor

submit_job(job: AssessmentJob) -> JobReceipt

wait_for_result(
    *,
    job_id: str,
    timeout_seconds: int
) -> WorkerResult

fetch_artifact(
    *,
    transfer_reference: str
) -> bytes

cancel_job(*, job_id: str) -> None