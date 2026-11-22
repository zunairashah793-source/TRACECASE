
from pathlib import Path

from tracecase.network.nmap_parser import parse_nmap_xml
from tracecase.network.pcap_parser import analyze_pcap
from tracecase.network.lab_evidence import analyze_lab_evidence


LAB_EVIDENCE_TYPES = {
    "system_info",
    "process_list",
    "service_list",
    "network_connections",
    "system_log",
    "test_file",
}


def collect_network_findings(
    *,
    indicator: str,
    indicator_type: str,
    artifact_type: str,
    artifact_path: Path,
    source_tool: str,
) -> list[dict]:
    """Route an artifact to its appropriate network evidence parser."""

    if not isinstance(artifact_type, str) or not artifact_type.strip():
        raise ValueError("artifact_type must be a non-empty string")

    artifact_type = artifact_type.strip().lower()

    if artifact_type == "nmap_xml":
        return parse_nmap_xml(
            artifact_path=artifact_path,
            indicator=indicator,
            indicator_type=indicator_type,
        )

    if artifact_type in {"pcap", "pcapng"}:
        return analyze_pcap(
            artifact_path=artifact_path,
            indicator=indicator,
            indicator_type=indicator_type,
        )

    if artifact_type in LAB_EVIDENCE_TYPES:
        return analyze_lab_evidence(
            artifact_path=artifact_path,
            artifact_type=artifact_type,
            indicator=indicator,
            indicator_type=indicator_type,
            source_tool=source_tool,
        )

    raise ValueError(
        f"Unsupported network artifact type: {artifact_type}"
    )
