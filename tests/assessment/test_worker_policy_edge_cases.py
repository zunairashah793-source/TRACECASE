import unittest

from tracecase.network.worker_policy import (
    validate_job_policy,
)


class TestWorkerPolicyEdgeCases(unittest.TestCase):

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

    def test_reject_non_dictionary_job(self):
        with self.assertRaises(ValueError):
            validate_job_policy(
                job=[],
                policy=self.policy,
                authenticated_controller_id="approved-controller",
            )

    def test_reject_non_dictionary_policy(self):
        with self.assertRaises(ValueError):
            validate_job_policy(
                job=self.job,
                policy=[],
                authenticated_controller_id="approved-controller",
            )

    def test_reject_wrong_worker_id(self):
        job = self.job.copy()
        job["worker_id"] = "another-worker"

        with self.assertRaises(ValueError):
            validate_job_policy(
                job=job,
                policy=self.policy,
                authenticated_controller_id="approved-controller",
            )

    def test_reject_unsupported_operation(self):
        job = self.job.copy()
        job["operation"] = "unknown_operation"

        with self.assertRaises(ValueError):
            validate_job_policy(
                job=job,
                policy=self.policy,
                authenticated_controller_id="approved-controller",
            )
