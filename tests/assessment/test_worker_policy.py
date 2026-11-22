
import json
import tempfile
import unittest
from pathlib import Path

from tracecase.network.worker_policy import (
    load_worker_policy,
    validate_job_policy,
)


class TestWorkerPolicy(unittest.TestCase):

    def setUp(self):
        self.policy = {
            "worker_id": "local-lab-worker",
            "allowed_controllers": ["approved-controller"],
            "targets": {
                "lab-target-1": {
                    "addresses": ["192.0.2.10"],
                    "ports": [80, 443],
                    "operations": {
                        "nmap_scan": ["lab-nmap-profile"],
                        "pcap_capture": ["lab-capture-profile"],
                        "post_access_collect": ["lab-evidence-profile"],
                    },
                }
            },
        }

        self.job = {
            "worker_id": "local-lab-worker",
            "target_id": "lab-target-1",
            "approved_target_addresses": ["192.0.2.10"],
            "allowed_ports": [80],
            "operation": "nmap_scan",
            "profile_id": "lab-nmap-profile",
        }

    # POLICY LOADING TESTS

    def test_load_valid_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(self.policy), encoding="utf-8")

            result = load_worker_policy(path)

            self.assertEqual(result["worker_id"], "local-lab-worker")

    def test_missing_policy_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.json"

            with self.assertRaises(ValueError):
                load_worker_policy(path)

    def test_invalid_json_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text("{invalid json", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_worker_policy(path)

    def test_reject_unexpected_policy_field(self):
        policy = json.loads(json.dumps(self.policy))
        policy["command"] = "unexpected"

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_worker_policy(path)

    def test_reject_unexpected_target_field(self):
        policy = json.loads(json.dumps(self.policy))
        policy["targets"]["lab-target-1"]["executable"] = "unexpected"

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_worker_policy(path)

    def test_reject_missing_policy_field(self):
        policy = json.loads(json.dumps(self.policy))
        del policy["worker_id"]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_worker_policy(path)

    def test_reject_invalid_policy_ip(self):
        policy = json.loads(json.dumps(self.policy))
        policy["targets"]["lab-target-1"]["addresses"] = [
            "192.0.2.999"
        ]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_worker_policy(path)

    def test_reject_cidr_target_address(self):
        policy = json.loads(json.dumps(self.policy))
        policy["targets"]["lab-target-1"]["addresses"] = [
            "192.0.2.0/24"
        ]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_worker_policy(path)

    def test_reject_unsupported_policy_operation(self):
        policy = json.loads(json.dumps(self.policy))
        policy["targets"]["lab-target-1"]["operations"][
            "arbitrary_command"
        ] = ["unknown-profile"]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_worker_policy(path)

    # ADDITIONAL SECURITY TESTS

    def test_reject_duplicate_json_keys(self):
        policy_json = json.dumps(self.policy)

        policy_json = policy_json.replace(
            '"worker_id": "local-lab-worker"',
            '"worker_id": "local-lab-worker", '
            '"worker_id": "another-worker"',
            1,
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(policy_json, encoding="utf-8")

            with self.assertRaises(ValueError):
                load_worker_policy(path)

    def test_reject_duplicate_policy_addresses(self):
        policy = json.loads(json.dumps(self.policy))
        policy["targets"]["lab-target-1"]["addresses"] = [
            "192.0.2.10",
            "192.0.2.10",
        ]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_worker_policy(path)

    def test_reject_duplicate_policy_ports(self):
        policy = json.loads(json.dumps(self.policy))
        policy["targets"]["lab-target-1"]["ports"] = [80, 80]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")

            with self.assertRaises(ValueError):
                load_worker_policy(path)

    def test_reject_invalid_policy_passed_directly(self):
        policy = json.loads(json.dumps(self.policy))
        policy["worker_id"] = ""

        with self.assertRaises(ValueError):
            validate_job_policy(
                job=self.job,
                policy=policy,
                authenticated_controller_id="approved-controller",
            )

    def test_reject_missing_required_job_field(self):
        job = self.job.copy()
        del job["profile_id"]

        with self.assertRaises(ValueError):
            validate_job_policy(
                job=job,
                policy=self.policy,
                authenticated_controller_id="approved-controller",
            )

    # FILE SIZE SECURITY TEST

    def test_reject_oversized_policy_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_bytes(b"x" * (1024 * 1024 + 1))

            with self.assertRaises(ValueError):
                load_worker_policy(path)

    # APPROVED JOB TESTS

    def test_accept_approved_job(self):
        result = validate_job_policy(
            job=self.job,
            policy=self.policy,
            authenticated_controller_id="approved-controller",
        )

        self.assertTrue(result)

    # CONTROLLER VALIDATION

    def test_reject_unapproved_controller(self):
        with self.assertRaises(ValueError):
            validate_job_policy(
                job=self.job,
                policy=self.policy,
                authenticated_controller_id="unknown-controller",
            )

    # TARGET VALIDATION

    def test_reject_unapproved_target(self):
        job = self.job.copy()
        job["target_id"] = "unknown-target"

        with self.assertRaises(ValueError):
            validate_job_policy(
                job=job,
                policy=self.policy,
                authenticated_controller_id="approved-controller",
            )

    def test_reject_invalid_target_id_type(self):
        job = self.job.copy()
        job["target_id"] = ["invalid"]

        with self.assertRaises(ValueError):
            validate_job_policy(
                job=job,
                policy=self.policy,
                authenticated_controller_id="approved-controller",
            )

    # PORT VALIDATION

    def test_reject_unapproved_port(self):
        job = self.job.copy()
        job["allowed_ports"] = [8080]

        with self.assertRaises(ValueError):
            validate_job_policy(
                job=job,
                policy=self.policy,
                authenticated_controller_id="approved-controller",
            )

    def test_reject_empty_job_ports(self):
        job = self.job.copy()
        job["allowed_ports"] = []

        with self.assertRaises(ValueError):
            validate_job_policy(
                job=job,
                policy=self.policy,
                authenticated_controller_id="approved-controller",
            )

    # PROFILE VALIDATION

    def test_reject_unapproved_profile(self):
        job = self.job.copy()
        job["profile_id"] = "unknown-profile"

        with self.assertRaises(ValueError):
            validate_job_policy(
                job=job,
                policy=self.policy,
                authenticated_controller_id="approved-controller",
            )

    # UNEXPECTED JOB DATA

    def test_reject_unexpected_job_field(self):
        job = self.job.copy()
        job["command"] = "unexpected"

        with self.assertRaises(ValueError):
            validate_job_policy(
                job=job,
                policy=self.policy,
                authenticated_controller_id="approved-controller",
            )


if __name__ == "__main__":
    unittest.main()
