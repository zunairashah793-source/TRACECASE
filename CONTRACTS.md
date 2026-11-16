# TRACECASE — Shared Technical Contracts

**Version:** 2.1.1  
**Status:** Reviewed interface baseline with worker ownership and form-binding clarifications (implementation and physical testing not yet claimed)  
**Date:** 16 November 2026  
This document is the single source of truth for shared field names, enums, payloads, module boundaries, backend service signatures, worker jobs, and Flask routes. A member must not independently change these interfaces. Contract changes require a reviewed pull request and a version update.

> These are interface specifications and type contracts, not finished application code. The team implements them in the assigned modules.

---

## 1. Shared enums

### 1.1 Indicator types

```text
ipv4
ipv6
domain
subdomain
url
hostname
tls_certificate
```

`authorized_lab` is not an indicator type.

### 1.2 Target kinds

```text
external_public
authorized_lab
```

### 1.3 Case statuses

```text
open
closed
```

### 1.4 Operation types (database `investigation_runs.operation_type`)

```text
external_intelligence
authorized_assessment
nmap_import
pcap_analysis
lab_evidence_import
case_evidence_import
manual_observation
```

`authorized_assessment` is used for a worker-initiated assessment in either `local` or `remote` execution mode. It is deliberately not named `remote_assessment`, because the same service supports a local lab run.

### 1.5 Execution modes (database `investigation_runs.execution_mode`)

```text
local
remote
```

This field is non-null only for `authorized_assessment` runs. Artifact imports and passive external-intelligence runs leave it null. Evidence-import mode is represented by its import `operation_type`, not by an assessment execution mode.

### 1.6 Worker operations (AssessmentJob.operation)

```text
nmap_scan
pcap_capture
post_access_collect
```

These are worker commands, not database operation types. A worker job may contain exactly one operation. `post_access_collect` requires a separate explicit confirmation and a locally configured credential method. The worker does not accept arbitrary command strings.

### 1.7 Operation statuses

```text
queued
running
success
partial
failed
cancelled
```

### 1.8 Finding categories

```text
external_intelligence
network_analysis
security_assessment
post_access_evidence
analyst_observation
```

### 1.9 Finding statuses

```text
success
partial
unavailable
error
```

### 1.10 Confidence

```text
high
medium
low
unknown
```

### 1.11 Evidence integrity status

```text
not_verified
verified
mismatch
```

### 1.12 Artifact types

```text
nmap_xml
pcap
pcapng
system_info
process_list
service_list
network_connections
system_log
test_file
```

---

## 2. Identifier and timestamp rules

- All database identifiers are backend-generated UUID strings.
- Use UTC for all stored timestamps.
- Canonical timestamp format: `YYYY-MM-DDTHH:MM:SSZ`.
- Python must parse and validate actual calendar/time values; matching a text pattern alone is insufficient.
- Reject impossible values such as hour `25`, invalid dates, local time without an offset, or malformed timezone suffix.
- Do not trust client-generated IDs, timestamps, file paths, evidence hashes, or run statuses.

---

## 3. Database contracts

### 3.1 `cases`

| Field | Type/requirement |
|---|---|
| `case_id` | UUID text, primary key |
| `title` | Required non-empty text, length-limited |
| `description` | Optional text |
| `scope_description` | Required text describing the investigation scope |
| `status` | `open` or `closed` |
| `notes` | Optional text |
| `created_at_utc` | Required canonical UTC timestamp |
| `updated_at_utc` | Required canonical UTC timestamp |
| `closed_at_utc` | Nullable canonical UTC timestamp |

A closed case is terminal in the initial project version: it cannot receive new collection/assessment operations and there is no reopen route in the current contract. Closing a case must not erase its records. Reopening would require a later reviewed contract change.

### 3.2 `targets`

| Field | Type/requirement |
|---|---|
| `target_id` | UUID text, primary key |
| `case_id` | Required foreign key to `cases` |
| `indicator` | Required normalized indicator string |
| `indicator_type` | One of the seven indicator types |
| `target_kind` | `external_public` or `authorized_lab` |
| `display_name` | Optional display label |
| `active_testing_authorized` | Boolean; defaults to false |
| `scope_note` | Required for an authorized lab target |
| `authorization_note` | Required before active assessment; records how authority/scope was established, without storing secrets |
| `authorization_expires_at_utc` | Optional expiry; if present, must be in the future at job start |
| `notes` | Optional text |
| `created_at_utc` | Required canonical UTC timestamp |

Rules:

- `external_public` targets are passive-intelligence-only in this project baseline.
- `authorized_lab` targets may be assessed only when `active_testing_authorized` is true and the operation falls within the scope note.
- Private lab indicators must never be sent to public intelligence providers.
- Normalize domain names to lower-case IDNA form where applicable; normalize IP addresses with the standard library `ipaddress` module.
- URLs accept only `http` or `https` schemes. URL inspection must not become unrestricted crawling or unrestricted redirect following.
- TLS certificate indicators use a SHA-256 certificate fingerprint as the canonical indicator value. For this fingerprint target type, the TLS collector performs passive fingerprint/certificate lookups only. Live TLS handshakes are performed against validated public IP/domain/subdomain/hostname/HTTPS URL targets; use port 443 unless an explicit HTTPS URL port is supplied.

Recommended uniqueness: prevent duplicate identical indicators of the same type in the same case, unless the backend has a documented reason to allow separate target records.

### 3.3 `investigation_runs`

| Field | Type/requirement |
|---|---|
| `run_id` | UUID text, primary key |
| `case_id` | Required case foreign key |
| `target_id` | Nullable only for `case_evidence_import`; otherwise required target foreign key in same case |
| `operation_type` | One of the operation types |
| `status` | One of the operation statuses |
| `execution_mode` | Nullable; `local` or `remote` only when `operation_type` is `authorized_assessment` |
| `requested_by` | User/member identifier or local actor label; no account password or secret |
| `started_at_utc` | Nullable while queued; required once running |
| `completed_at_utc` | Nullable until terminal status |
| `input_summary_json` | Valid JSON object; no credentials or secret values |
| `outcome_summary` | Human-readable summary |
| `error_summary` | Nullable, sanitized error explanation |
| `worker_id` | Nullable server-selected worker identifier; no secret token. The browser must never submit or choose this field. |
| `created_at_utc` | Required canonical UTC timestamp |

Run state transitions:

```text
queued -> running -> success
                    -> partial
                    -> failed
                    -> cancelled
```

A terminal run cannot silently return to `running`. A retry creates a new run. A run record must be created before work begins so failures are traceable. For `authorized_assessment`, the backend selects an enrolled worker from server-side configuration based on target and execution mode; do not accept a worker ID from a browser form.

### 3.4 `findings`

| Field | Type/requirement |
|---|---|
| `finding_id` | UUID text, backend-generated primary key |
| `case_id` | Required case foreign key |
| `target_id` | Required target foreign key in same case |
| `run_id` | Required run foreign key in same case and target |
| `indicator` | Canonical indicator copied from the target for traceability |
| `indicator_type` | Must match the target's indicator type |
| `category` | One of finding categories |
| `source` | Required lower-case normalized source slug, e.g. `rdap`, `dns`, `nmap`, `tshark`, `ssh_evidence` |
| `collected_at_utc` | Required canonical UTC timestamp |
| `status` | One of finding statuses |
| `summary` | Required concise human-readable statement |
| `finding_json` | Required JSON object containing structured source result |
| `confidence` | One of confidence values |
| `limitations_json` | Required JSON array of strings; empty array is allowed |
| `source_url` | Nullable validated source URL |
| `evidence_reference` | Nullable; when present must refer to target-specific evidence for the same case, target, and run |

One payload represents one source-level result. Do not combine every source into one large finding. A missing key, timeout, rate limit, unsupported source, or malformed provider response must be represented honestly as `unavailable` or `error`, with an explanation in `limitations_json` and/or `summary`. When findings are created from one imported/worker-produced artifact, the backend associates that artifact's evidence reference during persistence; collectors/parsers do not invent or supply backend evidence IDs.

### 3.5 `evidence`

| Field | Type/requirement |
|---|---|
| `evidence_reference` | UUID text, backend-generated primary key |
| `case_id` | Required case foreign key |
| `target_id` | Nullable for case-wide evidence; otherwise target foreign key in same case |
| `run_id` | Required foreign key to the operation that received/imported/created this evidence; the run must belong to the same case and have the same `target_id` (including NULL for case-wide evidence) |
| `evidence_type` | One of the artifact types or an approved extension value |
| `original_filename` | Sanitized display-only name; never used as storage path |
| `stored_relative_path` | Backend-generated relative path beneath evidence root |
| `mime_type` | Detected/validated MIME type where possible |
| `size_bytes` | Non-negative integer, bounded by upload limits |
| `sha256` | 64-character lowercase hex digest calculated by backend |
| `source_tool` | Required source tool or method label |
| `collected_at_utc` | Nullable if source time genuinely unknown; do not invent it |
| `received_at_utc` | Required canonical UTC timestamp |
| `integrity_status` | `not_verified`, `verified`, or `mismatch` |
| `notes` | Optional text |

Evidence rules:

- The backend creates an operation run for every evidence intake and links the evidence record to that run.
- The backend generates the storage name and path.
- Never accept a client path as `stored_relative_path`.
- Resolve final paths against the configured evidence root and reject traversal, absolute paths, symlink escapes, and unexpected file types.
- Never overwrite an existing evidence file.
- Hash the exact received bytes.
- Re-hash on verification; mark tampering as `mismatch`.
- A target-specific evidence record must reference a run for the same case and target. Case-wide evidence (`target_id = NULL`) must reference a case-wide run (`target_id = NULL`).
- Case-wide evidence may appear in case reports but cannot be used as a target-specific finding's primary evidence reference under this contract.

### 3.6 `case_events`

| Field | Type/requirement |
|---|---|
| `event_id` | UUID text, primary key |
| `case_id` | Required case foreign key |
| `target_id` | Nullable target foreign key; NULL denotes a case-wide event |
| `run_id` | Nullable run foreign key |
| `finding_id` | Nullable finding foreign key |
| `evidence_reference` | Nullable evidence foreign key |
| `event_type` | Normalized event slug |
| `description` | Required human-readable event description |
| `event_data_json` | Valid JSON object; no secrets |
| `actor` | Local member/worker label; no password or token |
| `created_at_utc` | Required canonical UTC timestamp |

`case_events` is append-only for ordinary application flows. Do not edit or delete old activity to hide a failed or partial operation. Corrections are new events that refer to the earlier event/run. Every non-null target/run/finding/evidence reference must belong to the same case. For every referenced run/finding/evidence record, its `target_id` must exactly equal the event's `target_id`; NULL must match NULL. Enforce these relationships with composite foreign keys where practical and always validate them in backend code.

### 3.7 Required relationship constraints

Use composite parent keys so SQLite can enforce case/target/run consistency wherever the child fields are non-null. The schema should provide these candidate unique keys:

- `targets(target_id, case_id)` and `targets(target_id, case_id, indicator, indicator_type)`
- `investigation_runs(run_id, case_id, target_id)`
- `evidence(evidence_reference, case_id, target_id)` and `evidence(evidence_reference, case_id, target_id, run_id)`
- `findings(finding_id, case_id, target_id)` and `findings(finding_id, case_id, target_id, run_id)`

Use matching composite foreign keys for these relationships:

- `findings(target_id, case_id, indicator, indicator_type)` → `targets`;
- `findings(run_id, case_id, target_id)` → `investigation_runs`;
- `findings(evidence_reference, case_id, target_id, run_id)` → `evidence` when `evidence_reference` is not NULL;
- `evidence(target_id, case_id)` → `targets` when `target_id` is not NULL;
- `evidence(run_id, case_id, target_id)` → `investigation_runs`;
- `case_events(target_id, case_id)` → `targets`; `case_events(run_id, case_id, target_id)` → `investigation_runs`; `case_events(finding_id, case_id, target_id)` → `findings`; and `case_events(evidence_reference, case_id, target_id)` → `evidence`.

Each composite foreign key must reference a parent UNIQUE key with exactly the same ordered columns; the schema should include every candidate parent key listed above. SQLite treats a composite foreign key with a NULL child component as not requiring a parent match. Therefore, Python validation must explicitly enforce NULL-to-NULL equality for case-wide evidence and case-wide events (the only case-wide run type is `case_evidence_import`). Do not assume a composite foreign key alone enforces those case-wide rules.

---

## 4. FindingPayload contract

Collectors/parsers return a list of payloads with this exact shape. Backend IDs and relationships are added by the backend, not by collectors.

```text
FindingPayload:
    indicator: str
    indicator_type: str
    category: str
    source: str
    collected_at_utc: str
    status: str
    summary: str
    finding: dict
    confidence: str
    limitations: list[str]
    source_url: str | None
```

Rules:

- `finding` must be a JSON-serializable object, not an arbitrary class instance.
- `limitations` must be a list of strings.
- `source` is lowercase and stable.
- `indicator` and `indicator_type` must represent the target being investigated; discovered related indicators are placed in structured finding data/graph relationships, not silently substituted as the parent target.
- `collected_at_utc` is UTC and strictly valid.
- No payload may contain API keys, passwords, private keys, session cookies, or other secrets.
- Collectors do not write to SQLite and do not generate `finding_id`.

---

## 5. External intelligence module contract — Zunaira

**Package:** `tracecase/intelligence/`

**Files:**

- `ip_intel.py`
- `domain_intel.py`
- `tls_intel.py`
- `reputation.py`
- `__init__.py`

### 5.1 Public entry point

```text
collect_external_intelligence(
    *,
    indicator: str,
    indicator_type: str,
    target_kind: str
) -> list[FindingPayload]
```

### 5.2 Collector functions

```text
collect_ip_intel(*, indicator: str, indicator_type: str) -> list[FindingPayload]
collect_domain_intel(*, indicator: str, indicator_type: str) -> list[FindingPayload]
collect_tls_intel(*, indicator: str, indicator_type: str) -> list[FindingPayload]
collect_reputation(*, indicator: str, indicator_type: str) -> list[FindingPayload]
```

### 5.3 Responsibilities

- IP: RDAP, ASN/ISP, approximate GeoIP, and configured public reputation sources.
- Domain/subdomain/hostname: DNS records and relevant registration/reputation information where available.
- URL: parse and validate; enrich the hostname/domain and safe public metadata. Do not crawl arbitrary web pages.
- TLS: inspect public certificate metadata/fingerprint for a validated public host/port.
- Reputation: support free sources and optional API keys. Missing keys are reported as unavailable, not as a clean result.
- Return one source-level finding per source/result.
- Continue independent sources when one source fails.
- The backend calls this entry point only for `target_kind="external_public"`; the function independently rejects any target kind other than `external_public` and any private, loopback, link-local, reserved, or non-global address.
- For `indicator_type="tls_certificate"`, treat the indicator as a fingerprint lookup, not as a hostname to connect to.
- No database writes, Flask request/session use, or UI rendering.

---

## 6. Network analysis module contract — Malaika Parveen

**Package:** `tracecase/network/`

**Files:**

- `nmap_parser.py`
- `pcap_parser.py`
- `lab_evidence.py`
- `worker_policy.py`

Parveen also owns `tracecase/assessment/jobs.py` for worker-job parsing, schema validation, normalization, and worker-side acceptance helpers, plus `tracecase/assessment/worker_service.py`. The canonical shared model classes/enums (`AssessmentJob`, `JobReceipt`, `WorkerDescriptor`, `WorkerResult`, and `WorkerArtifact`) are defined only in `tracecase/contracts.py`, owned by Asim with review from affected members. Parveen imports and validates those types; she must not define duplicate public model classes/enums. Asim owns `tracecase/assessment/worker_client.py` and integrates it with backend orchestration.

### 6.1 Canonical artifact entry point

```text
collect_network_findings(
    *,
    indicator: str,
    indicator_type: str,
    artifact_type: str,
    artifact_path: Path,
    source_tool: str
) -> list[FindingPayload]
```

Supported artifact types are defined in Section 1.12.

### 6.2 Individual parser functions

```text
parse_nmap_xml(*, artifact_path: Path, indicator: str, indicator_type: str) -> list[FindingPayload]
analyze_pcap(*, artifact_path: Path, indicator: str, indicator_type: str) -> list[FindingPayload]
analyze_lab_evidence(*, artifact_path: Path, artifact_type: str, indicator: str, indicator_type: str, source_tool: str) -> list[FindingPayload]
```

### 6.3 Responsibilities

- Parse actual Nmap XML; do not infer results from filenames.
- Analyse actual saved PCAP/PCAPNG using TShark.
- Parse selected post-access artifacts such as system info, process list, service list, network connections, logs, and test files.
- Preserve limitations and source metadata.
- Return `FindingPayload` lists only; backend saves them.
- Do not call public intelligence providers.
- Do not implement case management or direct database writes.

### 6.4 Safety and process execution

Any process invocation must use a fixed executable path/configuration, list-form arguments, `shell=False`, timeout, bounded output, and an approved working directory. The parser must not execute arbitrary content found inside an uploaded artifact.

---

## 7. Assessment worker contract — Parveen, integrated by Asim

The worker is a separate Python process on the Windows host that has a direct route to the authorized lab target. It is never installed inside Metasploitable 2. The same worker package is used for Local Lab Mode and Classroom Live Mode:

- Local Lab Mode: worker runs on Zunaira's Windows host and reaches her Metasploitable VM through its Host-only adapter.
- Classroom Live Mode: worker runs on Khadija's Windows host and reaches the Metasploitable VM through that host's Host-only adapter.
- Laptop A's controller sends an authenticated job to Laptop B's worker over the selected secure transport. The worker executes the bounded operation locally on Laptop B and returns the artifacts/results.

This is remotely initiated/delegated assessment. The packets to the private VM originate from the target-side worker, not directly from Laptop A's physical network interface. Kali remains available for independent manual testing but is not required as the Flask worker runtime.

### 7.1 Worker responsibilities

- Register with a stable `worker_id` using local worker configuration. Worker identity is not a password or bearer secret.
- Accept jobs and exchange results/artifacts only over an authenticated controller-to-worker transport that protects message integrity and confidentiality.
- Accept only the defined job schema and worker-operation allow-list.
- Check that the authenticated controller identity, `worker_id`, `target_id`, and exact target addresses match the worker's locally configured policy.
- Do not attempt to query the controller's SQLite database: the worker is a separate process/machine and has no direct database access. Before issuing a job, the controller validates the case's authorization record and sets the job expiry no later than the recorded authorization expiry. It sends a non-secret authorization reference. The worker verifies the authenticated controller, job integrity, expiry, one-time nonce/job ID, and the target/port/operation/profile against its own local allow-list.
- Enforce the locally approved scan/capture/post-access profile, exact target address, explicit port list/limits, timeout, output-size cap, preconfigured capture interface, and safe output directory.
- Execute one bounded operation per job, save original artifacts, compute hashes, and return a structured result.
- Reject expired or replayed jobs (one-time nonce/job ID tracking persisted in worker-local state so a worker restart does not reopen old jobs).
- Never execute arbitrary shell commands, scripts, uploaded executables, caller-supplied executable paths, or arbitrary destination strings.
- Never act as a general remote desktop or unrestricted remote shell.

The `worker_id` is selected by the backend from its server-side worker configuration. The user-facing HTML form never accepts a worker ID. Each worker host has a local, untracked policy file (for example `instance/worker-policy.json`) mapping allowed `target_id` values to exact IP addresses, allowed ports, supported operations, and local profile IDs/interfaces. It is independent on Zunaira's and Khadija's machines and is never committed to Git. Worker credentials/keys live in local secret configuration or the chosen transport's device identity, never in the repository, database, job JSON, or logs. If the selected transport does not bind authenticated machine identity to protected job messages, the worker protocol must add a per-worker application-layer signature/HMAC with verification key material stored outside the repository on both ends.

### 7.2 AssessmentJob fields

```text
AssessmentJob:
    job_id: UUID string
    case_id: UUID string
    target_id: UUID string
    run_id: UUID string
    worker_id: str                    # backend-selected, never browser-supplied
    execution_mode: local | remote
    operation: nmap_scan | pcap_capture | post_access_collect
    target_indicator: str
    target_indicator_type: str
    approved_target_addresses: list[str]  # exact normalized IPs, not arbitrary CIDRs
    allowed_ports: list[int]               # explicit bounded ports; subset of local policy
    profile_id: str                        # operation-specific ID resolved only by worker-local configuration
    authorization_reference: str           # non-secret case authorization reference
    requested_at_utc: canonical UTC timestamp
    expires_at_utc: canonical UTC timestamp
    nonce: unique one-time value
```

Exactly one worker `operation` is submitted per job. The single `profile_id` must exist in the worker's local configuration for that operation: `nmap_scan` resolves to a fixed scan profile; `pcap_capture` resolves to a `dumpcap` capture profile with a preconfigured Host-only interface/filter/duration; `post_access_collect` resolves to a fixed read-only evidence profile. `dumpcap` performs capture; TShark analyses the resulting saved PCAP/PCAPNG in the analysis process. The same profile field is used by the orchestration function and frontend form. A profile identifier never creates permission or carries raw command arguments. The job cannot carry arbitrary shell text, a command array, interface name, capture filter, duration override, or executable path. For `post_access_collect`, the required credential is supplied/selected locally on the worker host and is never included in this job.

The worker must compare `approved_target_addresses` with its own local allow-list for the target and must ensure `allowed_ports` and `profile_id` are permitted by that local policy. The controller cannot create a new worker-side target permission merely by sending an AssessmentJob. No CIDR/range scanning is allowed in the initial project profile; target addresses and ports are explicit. The worker does not independently query the controller database; the controller is responsible for validating the authorization record and issuing an authenticated, integrity-protected job whose expiry does not exceed the authorization expiry.

### 7.3 Job receipt and worker descriptor

```text
WorkerDescriptor:
    worker_id: str
    execution_modes: list[local | remote]
    supported_operations: list[nmap_scan | pcap_capture | post_access_collect]
    allowed_target_ids: list[str]
    health_status: available | unavailable | unknown

JobReceipt:
    job_id: UUID string
    worker_id: str
    accepted_at_utc: canonical UTC timestamp
    status: queued | running
```

The descriptor is internal controller metadata returned by server-side worker selection. It contains no credentials, private keys, or bearer tokens. The receipt confirms acceptance only; it does not claim that the operation succeeded.

### 7.4 WorkerResult fields

```text
WorkerResult:
    job_id: UUID string
    worker_id: str
    status: success | partial | failed | cancelled
    started_at_utc: canonical UTC timestamp
    completed_at_utc: canonical UTC timestamp
    summary: str
    artifacts: list[WorkerArtifact]
    limitations: list[str]
    error_code: str | None
```

```text
WorkerArtifact:
    artifact_id: UUID string
    artifact_type: approved artifact type
    filename: display-only original name
    size_bytes: non-negative integer
    sha256: 64-character lowercase hex digest
    transfer_reference: opaque authenticated, expiring artifact reference
    source_tool: str
    collected_at_utc: canonical UTC timestamp | None
```

The receiving backend must independently fetch and verify the transferred bytes and calculate its own SHA-256. It must not trust the worker-supplied hash alone. Each artifact is stored as an Evidence record before its parser findings are persisted. For findings parsed from a single artifact, the backend attaches that evidence reference during `save_findings`; if multiple artifacts are present, process/save each artifact separately so the correct evidence reference is attached.

### 7.5 Transport-independent controller interface

`worker_client.py` defines the controller-side operations, independent of the selected VPN/transport provider:

```text
select_worker(*, target_id: str, execution_mode: str) -> WorkerDescriptor
submit_job(job: AssessmentJob) -> JobReceipt
wait_for_result(*, job_id: str, timeout_seconds: int) -> WorkerResult
fetch_artifact(*, transfer_reference: str) -> bytes
cancel_job(*, job_id: str) -> None
```

The transport adapter authenticates the worker and protects job/result/artifact traffic. The actual provider and its identity model are selected separately after evaluating privacy, accounts, Windows compatibility, NAT/CGNAT, routing, firewall behaviour, cost, and data handling. The public Flask route does not expose the provider-specific API.

### 7.6 Post-access operation

Post-access collection is a separate, explicitly authorized worker operation. It uses a fixed read-only collector profile and a credential stored/entered locally on the worker host. Only approved evidence types (system info, process list, services, network connections, selected logs/test files) may be collected. The worker must never accept an arbitrary remote command field. The result records the actual access method and level; authenticated SSH is reported as authenticated remote access, not automatically full system compromise.

## 8. OperationSummary contract

Backend orchestration functions return this normalized summary to routes and the frontend:

```text
OperationSummary:
    run_id: UUID string
    case_id: UUID string
    target_id: UUID string | None
    operation_type: str
    execution_mode: local | remote | None
    status: queued | running | success | partial | failed | cancelled
    summary: str
    finding_ids: list[str]
    evidence_references: list[str]
    limitations: list[str]
    error_summary: str | None
```

`OperationSummary` contains only saved identifiers and sanitized status information. It never contains credentials, local filesystem paths, transport tokens, or raw secret configuration. The initial project version uses a bounded synchronous request for one worker job: the backend creates the run, submits the job, waits within the configured timeout, stores returned artifacts/findings, and returns the final saved summary. If the worker does not finish before the bound, the controller requests cancellation where possible, records the timeout/failure honestly, and leaves the run history visible. The run-detail route supports later review of the persisted outcome.

---

## 9. Backend services contract — Malaika Asim

**Shared type definitions:** `tracecase/contracts.py` (Python enums and typed data models for shared payloads/jobs/results). Asim implements this small common module with review from all affected members; every other module imports these definitions rather than making private copies.

**Package:** `tracecase/core/`

**Files:** `database.py`, `schema.sql`, `validators.py`, `cases.py`, `targets.py`, `runs.py`, `findings.py`, `evidence.py`, `events.py`, `orchestration.py`.

### 9.1 Database

```text
get_connection() -> sqlite3.Connection
initialize_database() -> None
```

Every connection enables foreign keys, uses safe row access, and applies the configured busy timeout/transaction settings.

### 9.2 Cases

```text
create_case(data: CaseCreate) -> Case
get_case(case_id: str) -> Case | None
list_cases(filters: CaseFilters | None = None) -> list[Case]
update_case(data: CaseUpdate) -> Case
close_case(case_id: str) -> Case
```

### 9.3 Targets

```text
create_target(case_id: str, data: TargetCreate) -> Target
get_target(case_id: str, target_id: str) -> Target | None
list_targets(case_id: str) -> list[Target]
```

All target lookups are case-scoped. A target identifier from another case must not be accepted.

### 9.4 Runs

```text
create_run(data: RunCreate) -> InvestigationRun
update_run_status(run_id: str, status: str, *, summary: str | None = None, error_summary: str | None = None) -> InvestigationRun
get_run(case_id: str, run_id: str) -> InvestigationRun | None
list_runs(case_id: str, target_id: str | None = None) -> list[InvestigationRun]
```

### 9.5 Findings

```text
validate_finding(payload: FindingPayload, *, target: Target) -> ValidatedFinding
save_findings(*, case_id: str, target_id: str, run_id: str, findings: list[FindingPayload], primary_evidence_reference: str | None = None) -> list[Finding]
list_findings(case_id: str, target_id: str | None = None, filters: FindingFilters | None = None) -> list[Finding]
get_finding(case_id: str, finding_id: str) -> Finding | None
add_manual_observation(*, case_id: str, target_id: str, summary: str, details: str, confidence: str, limitations: list[str]) -> OperationSummary
```

`save_findings` validates the full batch before opening the write transaction. The batch is all-or-nothing. Backend creates `finding_id` and attaches the case, target, run, and evidence reference. `add_manual_observation` creates a target-specific `manual_observation` run and an `analyst_observation` finding; the details are stored as structured JSON and the source is `analyst_manual`.

### 9.6 Evidence

```text
save_evidence_file(*, case_id: str, target_id: str | None, run_id: str, uploaded_file, evidence_type: str, source_tool: str, notes: str | None = None) -> Evidence
verify_evidence(case_id: str, evidence_reference: str) -> Evidence
list_evidence(case_id: str, target_id: str | None = None) -> list[Evidence]
get_evidence_path(case_id: str, evidence_reference: str) -> Path | None
```

`save_evidence_file` validates size/type, generates a collision-safe name, stores under the configured evidence root, calculates SHA-256, creates metadata, and cleans up the file if the database transaction fails. It never overwrites an existing file.

### 9.7 Events

```text
append_case_event(data: CaseEventCreate) -> CaseEvent
list_case_events(case_id: str, target_id: str | None = None) -> list[CaseEvent]
```

### 9.8 Orchestration

```text
run_external_investigation(*, case_id: str, target_id: str) -> OperationSummary
import_network_artifact(*, case_id: str, target_id: str, uploaded_file, artifact_type: str, source_tool: str, notes: str | None = None) -> OperationSummary
run_assessment_job(*, case_id: str, target_id: str, execution_mode: str, operation: str, profile_id: str, authorization_confirmed: bool) -> OperationSummary
import_case_evidence(*, case_id: str, uploaded_file, evidence_type: str, source_tool: str, notes: str | None = None) -> Evidence
```

Orchestration creates a run before starting work, selects the worker server-side, calls the controller client, fetches and verifies returned artifacts, stores each artifact, parses it, saves findings with the matching `primary_evidence_reference`, updates run status, and appends case events. Partial failure must remain visible. `save_findings` validates that the evidence reference (when supplied) belongs to the same case, target, and run. `save_evidence_file` also validates that the referenced run's `target_id` exactly matches the evidence `target_id`; NULL must match NULL for case-wide evidence.

---

## 10. Frontend/backend routes contract — Khadija + Asim

All paths and methods are canonical. The `web` blueprint uses endpoint names such as `web.dashboard`, `web.list_cases`, and `web.target_detail`.

| Method | Path | Handler responsibility |
|---|---|---|
| GET | `/` | Dashboard |
| GET | `/cases` | List cases |
| POST | `/cases` | Create case |
| GET | `/cases/<case_id>` | Case detail |
| GET | `/cases/<case_id>/runs/<run_id>` | Current run status and saved operation summary |
| POST | `/cases/<case_id>/update` | Update case |
| POST | `/cases/<case_id>/close` | Close case |
| POST | `/cases/<case_id>/targets` | Add target |
| GET | `/cases/<case_id>/targets/<target_id>` | Target detail/results |
| POST | `/cases/<case_id>/targets/<target_id>/external` | Start external collection |
| POST | `/cases/<case_id>/targets/<target_id>/observations` | Add a manual analyst observation |
| POST | `/cases/<case_id>/targets/<target_id>/assessment` | Queue an authorized assessment in local or remote execution mode |
| POST | `/cases/<case_id>/targets/<target_id>/nmap` | Import Nmap XML |
| POST | `/cases/<case_id>/targets/<target_id>/pcap` | Import/analyse PCAP |
| POST | `/cases/<case_id>/targets/<target_id>/evidence` | Upload target evidence |
| POST | `/cases/<case_id>/evidence` | Upload case-wide evidence |
| GET | `/cases/<case_id>/findings` | Findings page |
| GET | `/cases/<case_id>/evidence` | Evidence page |
| GET | `/cases/<case_id>/evidence/<evidence_reference>/download` | Safe download |
| GET | `/cases/<case_id>/timeline-data` | Timeline JSON |
| GET | `/cases/<case_id>/graph-data` | Graph JSON |
| GET | `/cases/<case_id>/map-data` | Map JSON |
| GET | `/cases/<case_id>/report-preview` | HTML report preview |
| GET | `/cases/<case_id>/report.pdf` | PDF export |
| GET | `/cases/<case_id>/report.csv` | CSV export |

### 10.1 Form field names

**Create case:** `title`, `description`, `scope_description`  
**Add target:** `indicator`, `indicator_type`, `target_kind`, `display_name`, `active_testing_authorized`, `scope_note`, `authorization_note`, `authorization_expires_at_utc`, `notes`  
**Nmap upload:** `nmap_file`  
**PCAP upload:** `pcap_file`  
**Evidence upload:** `evidence_file`, `evidence_type`, `source_tool`, `notes`  
**Manual observation:** `summary`, `details`, `confidence`, `limitations` (string list or newline-separated text validated by backend).  
**Assessment:** `execution_mode` (`local` or `remote`), `operation` (one of `nmap_scan`, `pcap_capture`, `post_access_collect`), `profile_id`, and `authorization_confirmed` (boolean checkbox). This checkbox confirms that the operator has reviewed the recorded authorization/scope for this operation; it does not create or replace authorization. The backend must independently verify `target_kind="authorized_lab"`, `active_testing_authorized=true`, the stored scope/authorization note, case status, permitted target/ports, and any authorization expiry before issuing a job. `worker_id` is selected by the backend and is never accepted from the browser. No arbitrary command, target address override, port range, capture-interface, capture-filter, duration, credential, or executable-path field.

### 10.2 Security requirements

- CSRF protection on all modifying routes.
- Jinja autoescaping; no unsafe rendering of provider or artifact content.
- Case/target ownership checks on every nested route.
- Strict upload size and format limits.
- Safe path handling for downloads.
- Do not expose raw filesystem paths or secret configuration in responses.
- Debug mode disabled for classroom demonstration.
- Bind locally by default; only expose the app through the selected secure transport when needed.

---

## 11. Report data contract

`reports/data.py` prepares one canonical report object consumed by HTML preview, PDF, and CSV export.

Minimum sections:

```text
ReportData:
    generated_at_utc
    case
    scope
    targets[]
    investigation_runs[]
    findings[]
    evidence[]
    timeline_events[]
    limitations[]
    source_attribution[]
    summary_counts
```

The UI/PDF/CSV may format the information differently, but they must not disagree about which findings, evidence, statuses, or timestamps exist. Unavailable or unverified information remains clearly labelled.

---

## 12. Graph and map data rules

### 11.1 Graph

Graph nodes/edges are generated from actual target, finding, evidence, and related-indicator records. Every edge must have a traceable source finding or documented relationship. Do not invent people or attribute network infrastructure to a person.

### 11.2 Map

Map points use approximate GeoIP data only. Missing coordinates are omitted. A displayed map must say that IP geolocation is approximate. Use local/static map assets where feasible; any external map service requires attribution and a documented privacy/availability decision.

---

## 13. Test directory and commands contract

Recommended test layout:

```text
tests/
├── core/
│   ├── test_contracts.py
│   ├── test_database.py
│   ├── test_cases.py
│   ├── test_targets.py
│   ├── test_runs.py
│   ├── test_findings.py
│   ├── test_evidence.py
│   └── test_events.py
├── intelligence/
│   ├── test_ip_intel.py
│   ├── test_domain_intel.py
│   ├── test_tls_intel.py
│   └── test_reputation.py
├── network/
│   ├── test_nmap_parser.py
│   ├── test_pcap_parser.py
│   └── test_lab_evidence.py
├── assessment/
│   ├── test_jobs.py
│   ├── test_worker_policy.py
│   ├── test_worker_service.py
│   └── test_worker_client.py
├── reports/
│   ├── test_report_data.py
│   └── test_exporter.py
├── web/
│   ├── test_routes.py
│   ├── test_forms.py
│   └── test_templates.py
└── integration/
    ├── test_external_workflow.py
    ├── test_network_workflow.py
    ├── test_remote_worker_workflow.py
    └── test_complete_case.py
```

Baseline verification commands after implementation:

```text
py -3.14 -m compileall -q tracecase tests
py -3.14 -m pytest -q
```

Database checks:

```sql
PRAGMA foreign_key_check;
PRAGMA integrity_check;
```

Expected: no rows from `foreign_key_check`; `ok` from `integrity_check`.

---

## 14. Change-control rules

A change requires a shared-contract update if it changes:

- field names or types;
- enums or status transitions;
- database relationships;
- `FindingPayload`;
- `AssessmentJob` or `WorkerResult`;
- module entry-point signatures;
- route paths/methods/form names; or
- report data shape.

The pull request must identify affected members, include tests, update this document, and be merged before dependent work is changed. No member should create a private variant of a shared contract.
