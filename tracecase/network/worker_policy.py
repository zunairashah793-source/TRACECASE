
import ipaddress
import json
from pathlib import Path


SUPPORTED_OPERATIONS = frozenset({
    "nmap_scan",
    "pcap_capture",
    "post_access_collect",
})

ALLOWED_POLICY_FIELDS = frozenset({
    "worker_id",
    "allowed_controllers",
    "targets",
})

ALLOWED_TARGET_FIELDS = frozenset({
    "addresses",
    "ports",
    "operations",
})

ALLOWED_JOB_FIELDS = frozenset({
    "job_id",
    "case_id",
    "target_id",
    "run_id",
    "worker_id",
    "execution_mode",
    "operation",
    "target_indicator",
    "target_indicator_type",
    "approved_target_addresses",
    "allowed_ports",
    "profile_id",
    "authorization_reference",
    "requested_at_utc",
    "expires_at_utc",
    "nonce",
})

REQUIRED_POLICY_JOB_FIELDS = frozenset({
    "worker_id",
    "target_id",
    "approved_target_addresses",
    "allowed_ports",
    "operation",
    "profile_id",
})

MAX_POLICY_SIZE = 1024 * 1024
MAX_PORT = 65535


def _reject_duplicate_keys(pairs):
    """Reject duplicate keys in JSON objects."""
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON keys are not allowed.")
        result[key] = value

    return result


def _reject_json_constant(value):
    """Reject NaN and Infinity values."""
    raise ValueError("Invalid JSON constant.")


def _validate_nonempty_string(value, field_name):
    """Validate a required non-empty string."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Invalid {field_name}.")
    return True


def _validate_ip_addresses(addresses):
    """Validate a list of exact, normalized IP addresses."""
    if not isinstance(addresses, list) or not addresses:
        raise ValueError("Invalid target addresses.")

    for address in addresses:
        if not isinstance(address, str):
            raise ValueError("Target address must be a string.")

        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as error:
            raise ValueError(
                "Invalid exact target IP address."
            ) from error

        if str(parsed) != address:
            raise ValueError(
                "Target IP address must be normalized."
            )

    if len(set(addresses)) != len(addresses):
        raise ValueError(
            "Duplicate target addresses are not allowed."
        )

    return True


def _validate_ports(ports, field_name):
    """Validate a non-empty list of unique port numbers."""
    if not isinstance(ports, list) or not ports:
        raise ValueError(f"Invalid {field_name}.")

    for port in ports:
        if type(port) is not int or not 1 <= port <= MAX_PORT:
            raise ValueError(f"Invalid port in {field_name}.")

    if len(set(ports)) != len(ports):
        raise ValueError("Duplicate ports are not allowed.")

    return True


def _validate_policy_data(policy):
    """Validate the complete structure of a worker policy."""
    if not isinstance(policy, dict):
        raise ValueError("Worker policy must be a JSON object.")

    if set(policy) != ALLOWED_POLICY_FIELDS:
        raise ValueError(
            "Worker policy must contain exactly the required fields."
        )

    _validate_nonempty_string(
        policy["worker_id"],
        "worker_id in policy",
    )

    controllers = policy["allowed_controllers"]

    if not isinstance(controllers, list) or not controllers:
        raise ValueError("Invalid allowed_controllers in policy.")

    for controller in controllers:
        _validate_nonempty_string(controller, "controller identity")

    if len(set(controllers)) != len(controllers):
        raise ValueError("Duplicate controllers are not allowed.")

    targets = policy["targets"]

    if not isinstance(targets, dict) or not targets:
        raise ValueError("Invalid targets in policy.")

    for target_id, target in targets.items():
        _validate_nonempty_string(target_id, "target ID")

        if not isinstance(target, dict):
            raise ValueError("Invalid target policy.")

        if set(target) != ALLOWED_TARGET_FIELDS:
            raise ValueError(
                "Target policy must contain exactly the required fields."
            )

        _validate_ip_addresses(target["addresses"])
        _validate_ports(target["ports"], "allowed ports")

        operations = target["operations"]

        if not isinstance(operations, dict) or not operations:
            raise ValueError("Invalid operation profiles.")

        if not set(operations).issubset(SUPPORTED_OPERATIONS):
            raise ValueError("Unsupported operation in local policy.")

        for operation, profiles in operations.items():
            if not isinstance(profiles, list) or not profiles:
                raise ValueError("Invalid profile list.")

            for profile in profiles:
                _validate_nonempty_string(
                    profile,
                    f"profile for {operation}",
                )

            if len(set(profiles)) != len(profiles):
                raise ValueError("Duplicate profiles are not allowed.")

    return True


def load_worker_policy(policy_path: Path) -> dict:
    """Load and validate a worker's local JSON policy."""
    policy_path = Path(policy_path)

    try:
        raw_bytes = policy_path.read_bytes()
    except OSError as error:
        raise ValueError(
            "Unable to read worker policy file."
        ) from error

    if len(raw_bytes) > MAX_POLICY_SIZE:
        raise ValueError("Worker policy file is too large.")

    try:
        raw_policy = raw_bytes.decode("utf-8")

        policy = json.loads(
            raw_policy,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )

    except (UnicodeError, ValueError) as error:
        raise ValueError(
            "Unable to read valid worker policy."
        ) from error

    _validate_policy_data(policy)

    return policy


def validate_job_policy(
    *,
    job: dict,
    policy: dict,
    authenticated_controller_id: str,
) -> bool:
    """
    Check a job against local worker permissions.

    The controller identity must come from an authenticated
    communication layer. This function does not authenticate it.
    """
    if not isinstance(job, dict):
        raise ValueError("Job must be a dictionary.")

    _validate_policy_data(policy)

    if not set(job).issubset(ALLOWED_JOB_FIELDS):
        raise ValueError("Unexpected field in worker job.")

    missing_fields = REQUIRED_POLICY_JOB_FIELDS - set(job)

    if missing_fields:
        raise ValueError(
            f"Missing required policy job fields: {sorted(missing_fields)}"
        )

    _validate_nonempty_string(
        authenticated_controller_id,
        "authenticated controller identity",
    )

    if authenticated_controller_id not in policy["allowed_controllers"]:
        raise ValueError("Controller is not locally approved.")

    if job["worker_id"] != policy["worker_id"]:
        raise ValueError("Worker identity does not match local policy.")

    target_id = job["target_id"]
    _validate_nonempty_string(target_id, "target ID")

    target = policy["targets"].get(target_id)

    if target is None:
        raise ValueError("Target is not locally approved.")

    requested_addresses = job["approved_target_addresses"]
    _validate_ip_addresses(requested_addresses)

    if set(requested_addresses) != set(target["addresses"]):
        raise ValueError(
            "Job addresses do not match local target policy."
        )

    requested_ports = job["allowed_ports"]
    _validate_ports(requested_ports, "requested ports")

    if not set(requested_ports).issubset(set(target["ports"])):
        raise ValueError("Job requests ports outside local policy.")

    operation = job["operation"]

    if (
        not isinstance(operation, str)
        or operation not in SUPPORTED_OPERATIONS
    ):
        raise ValueError("Unsupported worker operation.")

    permitted_profiles = target["operations"].get(operation, [])
    profile_id = job["profile_id"]

    if (
        not isinstance(profile_id, str)
        or profile_id not in permitted_profiles
    ):
        raise ValueError(
            "Profile is not approved for this operation."
        )

    return True
