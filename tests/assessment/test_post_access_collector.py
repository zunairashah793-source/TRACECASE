
import hashlib
import pytest

from tracecase.assessment.post_access_collector import (
    create_evidence_metadata,
    get_profile_commands,
    get_profile_ids,
)


def test_all_expected_profiles_are_available():
    assert get_profile_ids() == (
        "linux_system",
        "linux_processes",
        "linux_network",
        "linux_services",
        "linux_logs",
        "linux_full_readonly",
    )


@pytest.mark.parametrize("profile_id", get_profile_ids())
def test_every_profile_contains_predefined_operations(profile_id):
    commands = get_profile_commands(profile_id)

    assert commands
    assert all(
        isinstance(item, tuple)
        and len(item) == 2
        and all(isinstance(value, str) and value for value in item)
        for item in commands
    )


def test_full_profile_contains_all_evidence_categories():
    commands = get_profile_commands("linux_full_readonly")
    categories = {category for category, command in commands}

    assert categories == {
        "system_info",
        "process_list",
        "service_list",
        "network_connections",
        "system_log",
    }


@pytest.mark.parametrize(
    "profile_id",
    ["unknown", "", None, 123, "linux_system; arbitrary command"],
)
def test_unsupported_profiles_are_rejected(profile_id):
    with pytest.raises(ValueError):
        get_profile_commands(profile_id)


def test_profiles_do_not_include_privilege_escalation():
    for profile_id in get_profile_ids():
        commands = get_profile_commands(profile_id)

        for category, command in commands:
            assert not command.startswith("sudo ")
            assert not command.startswith("su ")


def test_evidence_metadata_contains_size_hash_and_timestamp():
    evidence = "Hello TRACECASE"

    metadata = create_evidence_metadata(evidence)

    assert metadata["size_bytes"] == len(evidence.encode("utf-8"))
    assert metadata["sha256"] == hashlib.sha256(
        evidence.encode("utf-8")
    ).hexdigest()
    assert metadata["collected_at_utc"]


def test_evidence_hash_is_consistent():
    evidence = "Hello TRACECASE"

    first = create_evidence_metadata(evidence)
    second = create_evidence_metadata(evidence)

    assert first["sha256"] == second["sha256"]
@pytest.mark.parametrize(
    "evidence",
    [123, None, [], {}],
)
def test_evidence_metadata_rejects_invalid_types(evidence):
    with pytest.raises(ValueError):
        create_evidence_metadata(evidence)
class FakeChannel:
    def __init__(self, exit_code=0):
        self.exit_code = exit_code

    def recv_exit_status(self):
        return self.exit_code
class FakeStdout:
    def __init__(self, content, exit_code=0):
        self.content = content
        self.channel = FakeChannel(exit_code)

    def read(self, size=-1):
        if size is None or size < 0:
            return self.content
        return self.content[:size]
class FakeSSHClient:
    def __init__(self, content=b"test evidence", exit_code=0):
        self.content = content
        self.exit_code = exit_code
        self.commands = []

    def exec_command(self, command, timeout=None):
        self.commands.append(command)
        return None, FakeStdout(self.content, self.exit_code), None


def test_collect_readonly_evidence_success():
    from tracecase.assessment.post_access_collector import collect_readonly_evidence

    client = FakeSSHClient(b"Linux test system")
    result = collect_readonly_evidence(client, "linux_system")

    assert len(result["evidence"]) == 3
    assert result["complete"] is True
    assert result["total_bytes"] > 0
    assert result["started_at_utc"].endswith("Z")
    assert result["completed_at_utc"].endswith("Z")
    assert result["started_at_utc"] <= result["completed_at_utc"]


def test_collect_readonly_evidence_enforces_output_limit():
    from tracecase.assessment.post_access_collector import collect_readonly_evidence

    client = FakeSSHClient(b"A" * 2000)
    result = collect_readonly_evidence(
        client, "linux_processes", max_output_bytes=1024
    )

    assert result["total_bytes"] == 1024
    assert result["complete"] is False


def test_collect_readonly_evidence_handles_command_failure():
    from tracecase.assessment.post_access_collector import collect_readonly_evidence

    client = FakeSSHClient(b"Permission denied", exit_code=1)
    result = collect_readonly_evidence(client, "linux_processes")

    assert result["evidence"][0]["exit_code"] == 1
    assert result["complete"] is False
    assert result["limitations"]
def test_create_worker_artifact_success():
    from tracecase.assessment.post_access_collector import (
        create_worker_artifact,
    )
    from tracecase.contracts import ArtifactType, WorkerArtifact

    evidence = {
        "evidence_type": "system_info",
        "content": b"Linux test system",
    }

    artifact = create_worker_artifact(
        evidence,
        transfer_reference="test-transfer-reference",
    )

    assert isinstance(artifact, WorkerArtifact)
    assert artifact.artifact_type == ArtifactType.SYSTEM_INFO
    assert artifact.size_bytes == len(b"Linux test system")
    assert artifact.sha256 == hashlib.sha256(
        b"Linux test system"
    ).hexdigest()
    assert artifact.transfer_reference == "test-transfer-reference"
    assert artifact.source_tool == "post_access_collector"
    assert artifact.filename.endswith(".txt")
    assert artifact.collected_at_utc


def test_create_worker_artifact_rejects_invalid_evidence():
    from tracecase.assessment.post_access_collector import (
        create_worker_artifact,
    )

    with pytest.raises(ValueError):
        create_worker_artifact(
            {"evidence_type": "unknown", "content": b"test"},
            transfer_reference="test-reference",
        )


def test_create_worker_artifact_rejects_invalid_content():
    from tracecase.assessment.post_access_collector import (
        create_worker_artifact,
    )

    with pytest.raises(ValueError):
        create_worker_artifact(
            {"evidence_type": "system_info", "content": 123},
            transfer_reference="test-reference",
        )
