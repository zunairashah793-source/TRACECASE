from dataclasses import fields

from tracecase.contracts import (
    ArtifactType,
    AssessmentJob,
    CaseStatus,
    Confidence,
    EvidenceIntegrityStatus,
    ExecutionMode,
    FindingCategory,
    FindingPayload,
    FindingStatus,
    IndicatorType,
    JobReceipt,
    OperationStatus,
    OperationSummary,
    OperationType,
    TargetKind,
    WorkerArtifact,
    WorkerDescriptor,
    WorkerHealthStatus,
    WorkerOperation,
    WorkerResult,
)


def test_indicator_types():
    assert {item.value for item in IndicatorType} == {
        "ipv4", "ipv6", "domain", "subdomain",
        "url", "hostname", "tls_certificate",
    }


def test_target_kinds():
    assert {item.value for item in TargetKind} == {
        "external_public", "authorized_lab",
    }


def test_case_statuses():
    assert {item.value for item in CaseStatus} == {
        "open", "closed",
    }


def test_operation_types():
    assert {item.value for item in OperationType} == {
        "external_intelligence",
        "authorized_assessment",
        "nmap_import",
        "pcap_analysis",
        "lab_evidence_import",
        "case_evidence_import",
        "manual_observation",
    }


def test_execution_modes():
    assert {item.value for item in ExecutionMode} == {
        "local", "remote",
    }


def test_worker_operations():
    assert {item.value for item in WorkerOperation} == {
        "nmap_scan", "pcap_capture", "post_access_collect",
    }


def test_operation_statuses():
    assert {item.value for item in OperationStatus} == {
        "queued", "running", "success",
        "partial", "failed", "cancelled",
    }


def test_finding_categories():
    assert {item.value for item in FindingCategory} == {
        "external_intelligence",
        "network_analysis",
        "security_assessment",
        "post_access_evidence",
        "analyst_observation",
    }


def test_finding_statuses():
    assert {item.value for item in FindingStatus} == {
        "success", "partial", "unavailable", "error",
    }


def test_confidence_values():
    assert {item.value for item in Confidence} == {
        "high", "medium", "low", "unknown",
    }


def test_evidence_integrity_values():
    assert {item.value for item in EvidenceIntegrityStatus} == {
        "not_verified", "verified", "mismatch",
    }


def test_artifact_types():
    assert {item.value for item in ArtifactType} == {
        "nmap_xml", "pcap", "pcapng", "system_info",
        "process_list", "service_list", "network_connections",
        "system_log", "test_file",
    }


def test_worker_health_values():
    assert {item.value for item in WorkerHealthStatus} == {
        "available", "unavailable", "unknown",
    }


def test_finding_payload_field_names():
    assert [field.name for field in fields(FindingPayload)] == [
        "indicator",
        "indicator_type",
        "category",
        "source",
        "collected_at_utc",
        "status",
        "summary",
        "finding",
        "confidence",
        "limitations",
        "source_url",
    ]


def test_assessment_job_uses_single_profile_id():
    names = {field.name for field in fields(AssessmentJob)}

    assert "profile_id" in names
    assert "nmap_profile" not in names
    assert "pcap_profile" not in names
    assert "post_access_profile" not in names
    assert "command" not in names


def test_worker_descriptor_has_no_credentials():
    names = {field.name for field in fields(WorkerDescriptor)}

    assert names == {
        "worker_id",
        "execution_modes",
        "supported_operations",
        "allowed_target_ids",
        "health_status",
    }


def test_job_receipt_field_names():
    assert [field.name for field in fields(JobReceipt)] == [
        "job_id", "worker_id", "accepted_at_utc", "status",
    ]


def test_worker_artifact_field_names():
    assert [field.name for field in fields(WorkerArtifact)] == [
        "artifact_id",
        "artifact_type",
        "filename",
        "size_bytes",
        "sha256",
        "transfer_reference",
        "source_tool",
        "collected_at_utc",
    ]


def test_worker_result_field_names():
    assert [field.name for field in fields(WorkerResult)] == [
        "job_id",
        "worker_id",
        "status",
        "started_at_utc",
        "completed_at_utc",
        "summary",
        "artifacts",
        "limitations",
        "error_code",
    ]


def test_operation_summary_field_names():
    assert [field.name for field in fields(OperationSummary)] == [
        "run_id",
        "case_id",
        "target_id",
        "operation_type",
        "execution_mode",
        "status",
        "summary",
        "finding_ids",
        "evidence_references",
        "limitations",
        "error_summary",
    ]
