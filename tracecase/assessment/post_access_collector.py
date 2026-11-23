
"""Read-only evidence collection for authorized Linux systems."""

import hashlib
from typing import Final

from tracecase.contracts import ArtifactType, WorkerArtifact
from tracecase.core.validators import (
    generate_id,
    utc_now,
    validate_required_text,
)


# Only predefined read-only commands are permitted.
_PROFILE_COMMANDS: Final = {
    "linux_system": (
        ("system_info", "uname -a"),
        ("system_info", "hostname"),
        ("system_info", "uptime"),
    ),
    "linux_processes": (
        ("process_list", "ps auxww"),
    ),
    "linux_network": (
        ("network_connections", "ip address show"),
        ("network_connections", "ip route show"),
    ),
    "linux_services": (
        ("service_list", "service --status-all"),
    ),
    "linux_logs": (
        ("system_log", "tail -n 100 /var/log/syslog"),
    ),
    "linux_full_readonly": (
        ("system_info", "uname -a"),
        ("system_info", "hostname"),
        ("system_info", "uptime"),
        ("process_list", "ps auxww"),
        ("network_connections", "ip address show"),
        ("network_connections", "ip route show"),
        ("service_list", "service --status-all"),
        ("system_log", "tail -n 100 /var/log/syslog"),
    ),
}


# Map collector evidence types to canonical shared artifact types.
_EVIDENCE_ARTIFACT_TYPES: Final = {
    "system_info": ArtifactType.SYSTEM_INFO,
    "process_list": ArtifactType.PROCESS_LIST,
    "service_list": ArtifactType.SERVICE_LIST,
    "network_connections": ArtifactType.NETWORK_CONNECTIONS,
    "system_log": ArtifactType.SYSTEM_LOG,
    "test_file": ArtifactType.TEST_FILE,
}


def get_profile_ids():
    """Return all available evidence profile names."""
    return tuple(_PROFILE_COMMANDS.keys())


def get_profile_commands(profile_id):
    """Return predefined commands for a supported profile."""
    if not isinstance(profile_id, str) or profile_id not in _PROFILE_COMMANDS:
        raise ValueError("Unsupported profile")

    return _PROFILE_COMMANDS[profile_id]


def create_evidence_metadata(evidence):
    """Calculate evidence size, SHA-256 and UTC collection timestamp."""

    if isinstance(evidence, str):
        evidence = evidence.encode("utf-8")

    if not isinstance(evidence, bytes):
        raise ValueError("Evidence must be text or bytes")

    return {
        "size_bytes": len(evidence),
        "sha256": hashlib.sha256(evidence).hexdigest(),
        "collected_at_utc": utc_now(),
    }


def collect_readonly_evidence(
    ssh_client,
    profile_id,
    *,
    timeout_seconds=60,
    max_output_bytes=5 * 1024 * 1024,
):
    """
    Collect evidence using predefined read-only commands.

    The SSH client must already be authenticated to an authorized
    lab system. This function does not accept arbitrary commands.
    """

    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool):
        raise ValueError("Invalid timeout")

    if not 1 <= timeout_seconds <= 3600:
        raise ValueError("Timeout must be between 1 and 3600 seconds")

    if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool):
        raise ValueError("Invalid output limit")

    if not 1024 <= max_output_bytes <= 100 * 1024 * 1024:
        raise ValueError("Output limit is outside the allowed range")

    if not callable(getattr(ssh_client, "exec_command", None)):
        raise ValueError("An authenticated SSH client is required")

    commands = get_profile_commands(profile_id)

    evidence_items = []
    limitations = []
    total_bytes = 0
    started_at_utc = utc_now()

    for evidence_type, command in commands:
        remaining = max_output_bytes - total_bytes

        if remaining <= 0:
            limitations.append("Maximum collection output reached")
            break

        try:
            _stdin, stdout, _stderr = ssh_client.exec_command(
                command,
                timeout=timeout_seconds,
            )

            content = stdout.read(remaining + 1)

            if isinstance(content, str):
                content = content.encode("utf-8")

            if not isinstance(content, bytes):
                raise ValueError("Collector returned invalid output")

            truncated = len(content) > remaining

            if truncated:
                content = content[:remaining]

            channel = getattr(stdout, "channel", None)
            exit_code = (
                channel.recv_exit_status()
                if channel is not None
                else None
            )

            evidence_items.append({
                "evidence_type": evidence_type,
                "content": content,
                "exit_code": exit_code,
                "metadata": create_evidence_metadata(content),
            })

            total_bytes += len(content)

            if exit_code not in (None, 0):
                limitations.append(
                    f"Collection command for {evidence_type} returned an error"
                )

            if truncated:
                limitations.append(
                    "Collection output was truncated at the configured limit"
                )
                break

        except Exception as exc:
            limitations.append(
                f"Collection failed for {evidence_type}: {type(exc).__name__}"
            )

    completed_at_utc = utc_now()

    return {
        "profile_id": profile_id,
        "started_at_utc": started_at_utc,
        "completed_at_utc": completed_at_utc,
        "evidence": evidence_items,
        "total_bytes": total_bytes,
        "limitations": limitations,
        "complete": not limitations,
    }

def create_worker_artifact(
    evidence_item,
    *,
    transfer_reference,
    filename=None,
    source_tool="post_access_collector",
):
    """
    Convert one collected evidence item into the shared WorkerArtifact model.

    transfer_reference must come from the actual artifact transfer layer.
    This function does not create or upload a transfer reference.
    """

    if not isinstance(evidence_item, dict):
        raise ValueError("Evidence item must be a dictionary")

    evidence_type = evidence_item.get("evidence_type")

    if evidence_type not in _EVIDENCE_ARTIFACT_TYPES:
        raise ValueError("Unsupported evidence type")

    content = evidence_item.get("content")

    if isinstance(content, str):
        content = content.encode("utf-8")

    if not isinstance(content, bytes):
        raise ValueError("Evidence content must be text or bytes")

    transfer_reference = validate_required_text(
        transfer_reference,
        "transfer_reference",
    )

    source_tool = validate_required_text(
        source_tool,
        "source_tool",
    )

    artifact_id = generate_id()

    if filename is None:
        filename = f"{evidence_type}-{artifact_id}.txt"

    filename = validate_required_text(filename, "filename")

    metadata = create_evidence_metadata(content)

    return WorkerArtifact(
        artifact_id=artifact_id,
        artifact_type=_EVIDENCE_ARTIFACT_TYPES[evidence_type],
        filename=filename,
        size_bytes=metadata["size_bytes"],
        sha256=metadata["sha256"],
        transfer_reference=transfer_reference,
        source_tool=source_tool,
        collected_at_utc=metadata["collected_at_utc"],
    )
