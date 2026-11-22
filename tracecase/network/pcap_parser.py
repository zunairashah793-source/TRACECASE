from datetime import datetime, timezone
import subprocess
from pathlib import Path
def analyze_pcap(
    *,
    artifact_path: Path,
    indicator: str,
    indicator_type: str
) -> list[dict]:
    """Convert PCAP analysis results into a FindingPayload-compatible list."""

    if not isinstance(indicator, str) or not indicator.strip():
        raise ValueError("indicator must be a non-empty string")

    if not isinstance(indicator_type, str) or not indicator_type.strip():
        raise ValueError("indicator_type must be a non-empty string")

    packets = parse_pcap_file(artifact_path)

    collected_at_utc = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    limitations = [
        "Analysis is limited to the first 500 packets.",
        "Packet details depend on the fields available in the capture.",
        "This analysis does not establish whether observed traffic is malicious."
    ]

    payload = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "category": "network_analysis",
        "source": "tshark",
        "collected_at_utc": collected_at_utc,
        "status": "success",
        "summary": (
            f"PCAP analysis completed: "
            f"{len(packets)} packet(s) analyzed."
        ),
        "finding": {
            "artifact_type": Path(artifact_path).suffix.lower().lstrip("."),
            "total_packets": len(packets),
            "packets": packets,
        },
        "confidence": "medium",
        "limitations": limitations,
        "source_url": None,
    }

    return [payload]

TSHARK_PATH = Path(
    r"C:\Program Files\Wireshark\tshark.exe"
)

MAX_PACKETS = 500
MAX_FILE_SIZE = 100 * 1024 * 1024
TIMEOUT_SECONDS = 30


def parse_pcap_file(artifact_path: Path) -> list[dict]:
    """Extract basic network information from a saved PCAP/PCAPNG file."""

    artifact_path = Path(artifact_path)

    if not artifact_path.is_file():
        raise ValueError("PCAP file does not exist.")

    if artifact_path.suffix.lower() not in (".pcap", ".pcapng"):
        raise ValueError("Unsupported capture file format.")

    if artifact_path.stat().st_size > MAX_FILE_SIZE:
        raise ValueError("Capture file exceeds the allowed size.")

    if not TSHARK_PATH.is_file():
        raise ValueError("TShark executable was not found.")

    command = [
        str(TSHARK_PATH),
        "-r", str(artifact_path),
        "-c", str(MAX_PACKETS),
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=TIMEOUT_SECONDS,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ValueError("TShark analysis timed out.") from error
    except OSError as error:
        raise ValueError("Unable to execute TShark.") from error

    if result.returncode != 0:
        raise ValueError("TShark could not read the capture file.")

    findings = []

    for line in result.stdout.splitlines():
        fields = line.split("\t")

        if len(fields) != 8:
            continue

        (
            frame_number,
            timestamp,
            ipv4_source,
            ipv6_source,
            ipv4_destination,
            ipv6_destination,
            protocol,
            info,
        ) = fields

        findings.append({
            "frame_number": frame_number,
            "timestamp": timestamp,
            "source": ipv4_source or ipv6_source or None,
            "destination": ipv4_destination or ipv6_destination or None,
            "protocol": protocol or None,
            "info": info or None,
        })

    return findings
