

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


def _parse_nmap_xml_document(artifact_path: Path):
    """Read and validate an Nmap XML document."""

    try:
        tree = ET.parse(artifact_path)
        root = tree.getroot()
    except (ET.ParseError, OSError) as error:
        raise ValueError(f"Unable to parse Nmap XML: {error}") from error

    if root.tag != "nmaprun":
        raise ValueError("Invalid Nmap XML: expected nmaprun root element")

    results = []

    for host in root.findall("host"):
        address_element = host.find("address")
        hostname_element = host.find("./hostnames/hostname")
        host_status_element = host.find("status")

        address = (
            address_element.get("addr")
            if address_element is not None
            else None
        )

        hostname = (
            hostname_element.get("name")
            if hostname_element is not None
            else None
        )

        ports = []

        for port in host.findall("./ports/port"):
            state_element = port.find("state")
            service_element = port.find("service")

            ports.append({
                "protocol": port.get("protocol"),
                "port": port.get("portid"),
                "state": (
                    state_element.get("state")
                    if state_element is not None
                    else None
                ),
                "service": (
                    service_element.get("name")
                    if service_element is not None
                    else None
                ),
            })

        results.append({
            "address": address,
            "hostname": hostname,
            "status": (
                host_status_element.get("state")
                if host_status_element is not None
                else None
            ),
            "ports": ports,
        })

    return root, results


def parse_nmap_xml_file(artifact_path: Path) -> list[dict]:
    """Extract host and port information from an Nmap XML file."""

    _, results = _parse_nmap_xml_document(artifact_path)
    return results


def parse_nmap_xml(
    *,
    artifact_path: Path,
    indicator: str,
    indicator_type: str
) -> list[dict]:
    """Convert an Nmap XML artifact into a FindingPayload list."""

    if not isinstance(indicator, str) or not indicator.strip():
        raise ValueError("indicator must be a non-empty string")

    if not isinstance(indicator_type, str) or not indicator_type.strip():
        raise ValueError("indicator_type must be a non-empty string")

    root, hosts = _parse_nmap_xml_document(artifact_path)

    total_ports = sum(len(host["ports"]) for host in hosts)

    collected_at_utc = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    limitations = [
        "Results reflect only the hosts and ports observed in this Nmap scan.",
        "A missing host or port in the XML does not prove that it does not exist."
    ]

    summary = (
        f"Nmap XML parsed successfully: "
        f"{len(hosts)} host(s) and {total_ports} port record(s) found."
    )

    finding = {
        "artifact_type": "nmap_xml",
        "scanner": root.get("scanner"),
        "nmap_version": root.get("version"),
        "scan_start": root.get("startstr"),
        "hosts": hosts,
        "total_hosts": len(hosts),
        "total_ports": total_ports,
    }

    payload = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "category": "network_analysis",
        "source": "nmap",
        "collected_at_utc": collected_at_utc,
        "status": "success",
        "summary": summary,
        "finding": finding,
        "confidence": "medium",
        "limitations": limitations,
        "source_url": None,
    }

    return [payload]
