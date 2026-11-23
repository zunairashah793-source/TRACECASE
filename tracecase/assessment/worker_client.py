"""
Controller-side assessment worker client.

Worker integration is not implemented yet.
These functions are placeholders to prevent accidental
use until the worker transport is configured.
"""


def select_worker(*, target_id: str, execution_mode: str):
    raise NotImplementedError(
        "Worker selection has not been implemented."
    )


def submit_job(job):
    raise NotImplementedError(
        "Worker job submission has not been implemented."
    )


def wait_for_result(*, job_id: str, timeout_seconds: int):
    raise NotImplementedError(
        "Worker result retrieval has not been implemented."
    )


def fetch_artifact(*, transfer_reference: str) -> bytes:
    raise NotImplementedError(
        "Worker artifact transfer has not been implemented."
    )


def cancel_job(*, job_id: str):
    raise NotImplementedError(
        "Worker cancellation has not been implemented."
    )