
from pathlib import Path
from unittest.mock import patch

import pytest

from tracecase.network.dispatcher import collect_network_findings


ARTIFACT = Path("sample.xml")


@patch("tracecase.network.dispatcher.parse_nmap_xml")
def test_dispatches_nmap_xml(mock_parser):
    mock_parser.return_value = [{"source": "nmap"}]

    result = collect_network_findings(
        indicator="192.0.2.10",
        indicator_type="ip",
        artifact_type="nmap_xml",
        artifact_path=ARTIFACT,
        source_tool="nmap",
    )

    assert result == [{"source": "nmap"}]
    mock_parser.assert_called_once_with(
        artifact_path=ARTIFACT,
        indicator="192.0.2.10",
        indicator_type="ip",
    )


@pytest.mark.parametrize("artifact_type", ["pcap", "pcapng"])
@patch("tracecase.network.dispatcher.analyze_pcap")
def test_dispatches_pcap_formats(mock_parser, artifact_type):
    mock_parser.return_value = [{"source": "tshark"}]

    result = collect_network_findings(
        indicator="192.0.2.10",
        indicator_type="ip",
        artifact_type=artifact_type,
        artifact_path=ARTIFACT,
        source_tool="tshark",
    )

    assert result == [{"source": "tshark"}]
    mock_parser.assert_called_once_with(
        artifact_path=ARTIFACT,
        indicator="192.0.2.10",
        indicator_type="ip",
    )


@pytest.mark.parametrize(
    "artifact_type",
    [
        "system_info",
        "process_list",
        "service_list",
        "network_connections",
        "system_log",
        "test_file",
    ],
)
@patch("tracecase.network.dispatcher.analyze_lab_evidence")
def test_dispatches_all_lab_evidence_types(
    mock_parser,
    artifact_type,
):
    mock_parser.return_value = [{"source": "lab_evidence"}]

    result = collect_network_findings(
        indicator="192.0.2.10",
        indicator_type="ip",
        artifact_type=artifact_type,
        artifact_path=ARTIFACT,
        source_tool="evidence_collector",
    )

    assert result == [{"source": "lab_evidence"}]
    mock_parser.assert_called_once_with(
        artifact_path=ARTIFACT,
        artifact_type=artifact_type,
        indicator="192.0.2.10",
        indicator_type="ip",
        source_tool="evidence_collector",
    )


@patch("tracecase.network.dispatcher.analyze_pcap")
def test_normalizes_artifact_type(mock_parser):
    mock_parser.return_value = []

    result = collect_network_findings(
        indicator="192.0.2.10",
        indicator_type="ip",
        artifact_type=" PCAPNG ",
        artifact_path=ARTIFACT,
        source_tool="tshark",
    )

    assert result == []
    mock_parser.assert_called_once()


@pytest.mark.parametrize(
    "artifact_type",
    ["", "   ", None, "unknown"],
)
def test_rejects_invalid_artifact_types(artifact_type):
    with pytest.raises(ValueError):
        collect_network_findings(
            indicator="192.0.2.10",
            indicator_type="ip",
            artifact_type=artifact_type,
            artifact_path=ARTIFACT,
            source_tool="test",
        )
