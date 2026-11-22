
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


@patch("tracecase.network.dispatcher.analyze_pcap")
def test_dispatches_pcap(mock_parser):
    mock_parser.return_value = [{"source": "tshark"}]

    result = collect_network_findings(
        indicator="192.0.2.10",
        indicator_type="ip",
        artifact_type="pcapng",
        artifact_path=ARTIFACT,
        source_tool="tshark",
    )

    assert result == [{"source": "tshark"}]
    mock_parser.assert_called_once()


@patch("tracecase.network.dispatcher.analyze_lab_evidence")
def test_dispatches_lab_evidence(mock_parser):
    mock_parser.return_value = [{"source": "ssh_evidence"}]

    result = collect_network_findings(
        indicator="192.0.2.10",
        indicator_type="ip",
        artifact_type="system_info",
        artifact_path=ARTIFACT,
        source_tool="ssh_evidence",
    )

    assert result == [{"source": "ssh_evidence"}]
    mock_parser.assert_called_once_with(
        artifact_path=ARTIFACT,
        artifact_type="system_info",
        indicator="192.0.2.10",
        indicator_type="ip",
        source_tool="ssh_evidence",
    )


def test_rejects_unsupported_artifact_type():
    with pytest.raises(ValueError):
        collect_network_findings(
            indicator="192.0.2.10",
            indicator_type="ip",
            artifact_type="unknown",
            artifact_path=ARTIFACT,
            source_tool="test",
        )


def test_rejects_empty_artifact_type():
    with pytest.raises(ValueError):
        collect_network_findings(
            indicator="192.0.2.10",
            indicator_type="ip",
            artifact_type="",
            artifact_path=ARTIFACT,
            source_tool="test",
        )
