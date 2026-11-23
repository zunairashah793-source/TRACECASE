from dataclasses import dataclass
from enum import StrEnum
from typing import Any


# ============================================================
# SHARED ENUMS
# ============================================================

class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    URL = "url"
    HOSTNAME = "hostname"
    TLS_CERTIFICATE = "tls_certificate"


class TargetKind(StrEnum):
    EXTERNAL_PUBLIC = "external_public"
    AUTHORIZED_LAB = "authorized_lab"


class CaseStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class OperationType(StrEnum):
    EXTERNAL_INTELLIGENCE = "external_intelligence"
    AUTHORIZED_ASSESSMENT = "authorized_assessment"
    NMAP_IMPORT = "nmap_import"
    PCAP_ANALYSIS = "pcap_analysis"
    LAB_EVIDENCE_IMPORT = "lab_evidence_import"
    CASE_EVIDENCE_IMPORT = "case_evidence_import"
    MANUAL_OBSERVATION = "manual_observation"


class ExecutionMode(StrEnum):
    LOCAL = "local"
    REMOTE = "remote"


class WorkerOperation(StrEnum):
    NMAP_SCAN = "nmap_scan"
    PCAP_CAPTURE = "pcap_capture"
    POST_ACCESS_COLLECT = "post_access_collect"


class OperationStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingCategory(StrEnum):
    EXTERNAL_INTELLIGENCE = "external_intelligence"
    NETWORK_ANALYSIS = "network_analysis"
    SECURITY_ASSESSMENT = "security_assessment"
    POST_ACCESS_EVIDENCE = "post_access_evidence"
    ANALYST_OBSERVATION = "analyst_observation"


class FindingStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class EvidenceIntegrityStatus(StrEnum):
    NOT_VERIFIED = "not_verified"
    VERIFIED = "verified"
    MISMATCH = "mismatch"


class ArtifactType(StrEnum):
    NMAP_XML = "nmap_xml"
    PCAP = "pcap"
    PCAPNG = "pcapng"
    SYSTEM_INFO = "system_info"
    PROCESS_LIST = "process_list"
    SERVICE_LIST = "service_list"
    NETWORK_CONNECTIONS = "network_connections"
    SYSTEM_LOG = "system_log"
    TEST_FILE = "test_file"


class WorkerHealthStatus(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


# ============================================================
# FINDING PAYLOAD
# ============================================================

@dataclass
class FindingPayload:
    indicator: str
    indicator_type: IndicatorType
    category: FindingCategory
    source: str
    collected_at_utc: str
    status: FindingStatus
    summary: str
    finding: dict[str, Any]
    confidence: Confidence
    limitations: list[str]
    source_url: str | None = None


# ============================================================
# ASSESSMENT WORKER JOB
# ============================================================

@dataclass
class AssessmentJob:
    job_id: str
    case_id: str
    target_id: str
    run_id: str
    worker_id: str
    execution_mode: ExecutionMode
    operation: WorkerOperation
    target_indicator: str
    target_indicator_type: IndicatorType
    approved_target_addresses: list[str]
    allowed_ports: list[int]
    profile_id: str
    authorization_reference: str
    requested_at_utc: str
    expires_at_utc: str
    nonce: str

# ============================================================
# TARGET MODELS
# ============================================================

@dataclass
class TargetCreate:
    indicator: str
    indicator_type: IndicatorType
    target_kind: TargetKind
    display_name: str | None = None
    active_testing_authorized: bool = False
    scope_note: str | None = None
    authorization_note: str | None = None
    authorization_expires_at_utc: str | None = None
    notes: str | None = None


@dataclass
class Target:
    target_id: str
    case_id: str
    indicator: str
    indicator_type: IndicatorType
    target_kind: TargetKind
    display_name: str | None
    active_testing_authorized: bool
    scope_note: str | None
    authorization_note: str | None
    authorization_expires_at_utc: str | None
    notes: str | None
    created_at_utc: str


# ============================================================
# WORKER DESCRIPTOR AND JOB RECEIPT
# ============================================================

@dataclass
class WorkerDescriptor:
    worker_id: str
    execution_modes: list[ExecutionMode]
    supported_operations: list[WorkerOperation]
    allowed_target_ids: list[str]
    health_status: WorkerHealthStatus


@dataclass
class JobReceipt:
    job_id: str
    worker_id: str
    accepted_at_utc: str
    status: OperationStatus


# ============================================================
# WORKER ARTIFACT
# ============================================================

@dataclass
class WorkerArtifact:
    artifact_id: str
    artifact_type: ArtifactType
    filename: str
    size_bytes: int
    sha256: str
    transfer_reference: str
    source_tool: str
    collected_at_utc: str | None = None


# ============================================================
# WORKER RESULT
# ============================================================

@dataclass
class WorkerResult:
    job_id: str
    worker_id: str
    status: OperationStatus
    started_at_utc: str
    completed_at_utc: str
    summary: str
    artifacts: list[WorkerArtifact]
    limitations: list[str]
    error_code: str | None = None


# ============================================================
# BACKEND OPERATION SUMMARY
# ============================================================

@dataclass
class OperationSummary:
    run_id: str
    case_id: str
    target_id: str | None
    operation_type: OperationType
    execution_mode: ExecutionMode | None
    status: OperationStatus
    summary: str
    finding_ids: list[str]
    evidence_references: list[str]
    limitations: list[str]
    error_summary: str | None = None
