
import pytest

from tracecase.reports.exporter import (
    export_case_report,
    export_case_csv,
)


@pytest.fixture
def report_data():
    return {
        "case": {
            "case_id": "case-001",
            "title": "TRACECASE Test Report",
            "status": "open",
            "scope_description": "Authorized laboratory",
            "description": "Testing PDF and CSV export",
        },
        "targets": [
            {
                "indicator": "192.168.56.10",
                "indicator_type": "ipv4",
                "target_kind": "authorized_lab",
            }
        ],
        "runs": [],
        "findings": [
            {
                "summary": "Test network finding",
                "category": "network_analysis",
                "confidence": "high",
            }
        ],
        "evidence": [
            {
                "original_filename": "capture.pcap",
                "evidence_type": "pcap",
                "sha256": "a" * 64,
            }
        ],
        "events": [
            {
                "created_at_utc": "2026-11-23T10:00:00Z",
                "description": "Investigation started",
            }
        ],
    }


def test_export_returns_pdf_bytes(report_data):
    result = export_case_report(report_data)

    assert isinstance(result, bytes)
    assert result.startswith(b"%PDF")
    assert len(result) > 0


def test_export_with_empty_collections():
    data = {
        "case": {
            "case_id": "case-002",
            "title": "Empty Report",
            "status": "open",
            "scope_description": "Testing",
            "description": "",
        },
        "targets": [],
        "runs": [],
        "findings": [],
        "evidence": [],
        "events": [],
    }

    result = export_case_report(data)

    assert result.startswith(b"%PDF")


def test_export_with_special_characters(report_data):
    report_data["case"]["title"] = "DNS & TLS <Investigation>"
    report_data["findings"][0]["summary"] = "DNS & TLS <review>"

    result = export_case_report(report_data)

    assert result.startswith(b"%PDF")
    assert len(result) > 0


def test_export_with_multiple_targets(report_data):
    report_data["targets"].append({
        "indicator": "example.com",
        "indicator_type": "domain",
        "target_kind": "external_public",
    })

    result = export_case_report(report_data)

    assert result.startswith(b"%PDF")


def test_csv_export_returns_utf8_csv(report_data):
    result = export_case_csv(report_data)

    assert isinstance(result, bytes)
    assert result.startswith(b"\xef\xbb\xbf")

    text = result.decode("utf-8-sig")
    assert "TRACECASE Investigation Report" in text
    assert "TRACECASE Test Report" in text


def test_csv_export_includes_report_records(report_data):
    result = export_case_csv(report_data)
    text = result.decode("utf-8-sig")

    assert "192.168.56.10" in text
    assert "Test network finding" in text
    assert "capture.pcap" in text
    assert "Investigation started" in text


def test_csv_export_handles_empty_collections():
    data = {
        "case": {
            "case_id": "case-002",
            "title": "Empty CSV Report",
            "status": "open",
            "scope_description": "Testing",
        },
        "targets": [],
        "runs": [],
        "findings": [],
        "evidence": [],
        "events": [],
    }

    result = export_case_csv(data)

    assert result.startswith(b"\xef\xbb\xbf")
    assert b"TARGETS" in result
    assert b"FINDINGS" in result
    assert b"EVIDENCE" in result
    assert b"CASE TIMELINE" in result
def test_csv_export_includes_investigation_runs(report_data):
    report_data["runs"] = [{
        "run_id": "run-001",
        "operation_type": "nmap_import",
        "status": "success",
        "execution_mode": None,
        "requested_by": "Malaika",
        "started_at_utc": "2026-11-23T10:00:00Z",
        "completed_at_utc": "2026-11-23T10:05:00Z",
        "outcome_summary": "Import completed",
        "error_summary": None,
    }]

    result = export_case_csv(report_data)
    text = result.decode("utf-8-sig")

    assert "INVESTIGATION RUNS" in text
    assert "run-001" in text
    assert "nmap_import" in text
    assert "Import completed" in text