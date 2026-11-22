
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    title TEXT NOT NULL CHECK(length(trim(title)) BETWEEN 1 AND 200),
    description TEXT,
    scope_description TEXT NOT NULL CHECK(length(trim(scope_description)) > 0),
    status TEXT NOT NULL DEFAULT 'open'
        CHECK(status IN ('open', 'closed')),
    notes TEXT,
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    closed_at_utc TEXT
);

CREATE TABLE IF NOT EXISTS targets (
    target_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    indicator TEXT NOT NULL CHECK(length(trim(indicator)) > 0),
    indicator_type TEXT NOT NULL CHECK(indicator_type IN (
        'ipv4', 'ipv6', 'domain', 'subdomain', 'url',
        'hostname', 'tls_certificate'
    )),
    target_kind TEXT NOT NULL CHECK(target_kind IN (
        'external_public', 'authorized_lab'
    )),
    display_name TEXT,
    active_testing_authorized INTEGER NOT NULL DEFAULT 0
        CHECK(active_testing_authorized IN (0, 1)),
    scope_note TEXT,
    authorization_note TEXT,
    authorization_expires_at_utc TEXT,
    notes TEXT,
    created_at_utc TEXT NOT NULL,

    UNIQUE(target_id, case_id),
    UNIQUE(target_id, case_id, indicator, indicator_type),
    UNIQUE(case_id, indicator, indicator_type),

    FOREIGN KEY(case_id) REFERENCES cases(case_id),

    CHECK(
        target_kind != 'authorized_lab'
        OR length(trim(COALESCE(scope_note, ''))) > 0
    )
);

CREATE TABLE IF NOT EXISTS investigation_runs (
    run_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    target_id TEXT,
    operation_type TEXT NOT NULL CHECK(operation_type IN (
        'external_intelligence', 'authorized_assessment',
        'nmap_import', 'pcap_analysis', 'lab_evidence_import',
        'case_evidence_import', 'manual_observation'
    )),
    status TEXT NOT NULL CHECK(status IN (
        'queued', 'running', 'success', 'partial',
        'failed', 'cancelled'
    )),
    execution_mode TEXT CHECK(
        execution_mode IS NULL OR execution_mode IN ('local', 'remote')
    ),
    requested_by TEXT NOT NULL,
    started_at_utc TEXT,
    completed_at_utc TEXT,
    input_summary_json TEXT NOT NULL DEFAULT '{}'
        CHECK(json_valid(input_summary_json)
              AND json_type(input_summary_json) = 'object'),
    outcome_summary TEXT,
    error_summary TEXT,
    worker_id TEXT,
    created_at_utc TEXT NOT NULL,

    UNIQUE(run_id, case_id, target_id),

    FOREIGN KEY(case_id) REFERENCES cases(case_id),
    FOREIGN KEY(target_id, case_id)
        REFERENCES targets(target_id, case_id),

    CHECK(
        (operation_type = 'case_evidence_import' AND target_id IS NULL)
        OR
        (operation_type != 'case_evidence_import' AND target_id IS NOT NULL)
    ),
    CHECK(
        (operation_type = 'authorized_assessment'
            AND execution_mode IS NOT NULL)
        OR
        (operation_type != 'authorized_assessment'
            AND execution_mode IS NULL)
    ),
    CHECK(status != 'running' OR started_at_utc IS NOT NULL),
    CHECK(
        status NOT IN ('success', 'partial', 'failed', 'cancelled')
        OR completed_at_utc IS NOT NULL
    )
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_reference TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    target_id TEXT,
    run_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    stored_relative_path TEXT NOT NULL,
    mime_type TEXT,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    sha256 TEXT NOT NULL CHECK(
        length(sha256) = 64
        AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_tool TEXT NOT NULL,
    collected_at_utc TEXT,
    received_at_utc TEXT NOT NULL,
    integrity_status TEXT NOT NULL CHECK(integrity_status IN (
        'not_verified', 'verified', 'mismatch'
    )),
    notes TEXT,

    UNIQUE(evidence_reference, case_id, target_id),
    UNIQUE(evidence_reference, case_id, target_id, run_id),

    FOREIGN KEY(case_id) REFERENCES cases(case_id),
    FOREIGN KEY(target_id, case_id)
        REFERENCES targets(target_id, case_id),
    FOREIGN KEY(run_id, case_id, target_id)
        REFERENCES investigation_runs(run_id, case_id, target_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL CHECK(indicator_type IN (
        'ipv4', 'ipv6', 'domain', 'subdomain', 'url',
        'hostname', 'tls_certificate'
    )),
    category TEXT NOT NULL CHECK(category IN (
        'external_intelligence', 'network_analysis',
        'security_assessment', 'post_access_evidence',
        'analyst_observation'
    )),
    source TEXT NOT NULL CHECK(length(trim(source)) > 0),
    collected_at_utc TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'success', 'partial', 'unavailable', 'error'
    )),
    summary TEXT NOT NULL,
    finding_json TEXT NOT NULL CHECK(
        json_valid(finding_json)
        AND json_type(finding_json) = 'object'
    ),
    confidence TEXT NOT NULL CHECK(confidence IN (
        'high', 'medium', 'low', 'unknown'
    )),
    limitations_json TEXT NOT NULL CHECK(
        json_valid(limitations_json)
        AND json_type(limitations_json) = 'array'
    ),
    source_url TEXT,
    evidence_reference TEXT,

    UNIQUE(finding_id, case_id, target_id),
    UNIQUE(finding_id, case_id, target_id, run_id),

    FOREIGN KEY(case_id) REFERENCES cases(case_id),
    FOREIGN KEY(target_id, case_id, indicator, indicator_type)
        REFERENCES targets(target_id, case_id, indicator, indicator_type),
    FOREIGN KEY(run_id, case_id, target_id)
        REFERENCES investigation_runs(run_id, case_id, target_id),
    FOREIGN KEY(evidence_reference, case_id, target_id, run_id)
        REFERENCES evidence(
            evidence_reference, case_id, target_id, run_id
        )
);

CREATE TABLE IF NOT EXISTS case_events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    target_id TEXT,
    run_id TEXT,
    finding_id TEXT,
    evidence_reference TEXT,
    event_type TEXT NOT NULL CHECK(length(trim(event_type)) > 0),
    description TEXT NOT NULL CHECK(length(trim(description)) > 0),
    event_data_json TEXT NOT NULL DEFAULT '{}'
        CHECK(json_valid(event_data_json)
              AND json_type(event_data_json) = 'object'),
    actor TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,

    FOREIGN KEY(case_id) REFERENCES cases(case_id),
    FOREIGN KEY(target_id, case_id)
        REFERENCES targets(target_id, case_id),
    FOREIGN KEY(run_id, case_id, target_id)
        REFERENCES investigation_runs(run_id, case_id, target_id),
    FOREIGN KEY(finding_id, case_id, target_id)
        REFERENCES findings(finding_id, case_id, target_id),
    FOREIGN KEY(evidence_reference, case_id, target_id)
        REFERENCES evidence(evidence_reference, case_id, target_id)
);

CREATE INDEX IF NOT EXISTS idx_targets_case_id
    ON targets(case_id);

CREATE INDEX IF NOT EXISTS idx_runs_case_id
    ON investigation_runs(case_id, created_at_utc);

CREATE INDEX IF NOT EXISTS idx_runs_target_id
    ON investigation_runs(target_id);

CREATE INDEX IF NOT EXISTS idx_findings_case_id
    ON findings(case_id);

CREATE INDEX IF NOT EXISTS idx_findings_target_id
    ON findings(target_id);

CREATE INDEX IF NOT EXISTS idx_findings_run_id
    ON findings(run_id);

CREATE INDEX IF NOT EXISTS idx_evidence_case_id
    ON evidence(case_id);

CREATE INDEX IF NOT EXISTS idx_evidence_target_id
    ON evidence(target_id);

CREATE INDEX IF NOT EXISTS idx_events_case_id
    ON case_events(case_id, created_at_utc);

CREATE INDEX IF NOT EXISTS idx_events_target_id
    ON case_events(target_id);
