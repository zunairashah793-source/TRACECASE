from datetime import datetime
import json
import tempfile
import unittest
from pathlib import Path

from tracecase.network.lab_evidence import (
    parse_lab_evidence_file,
    analyze_lab_evidence,
)
from datetime import datetime
class TestLabEvidenceParser(unittest.TestCase):
    def test_analyze_lab_evidence_returns_finding_payload(self):
        evidence_file = self.test_dir / "system_info.json"
        evidence_file.write_text(
            json.dumps({"hostname": "LAB-PC", "os": "Windows"}),
            encoding="utf-8",
        )

        results = analyze_lab_evidence(
            artifact_path=evidence_file,
            artifact_type="system_info",
            indicator="192.0.2.10",
            indicator_type="ip",
            source_tool="ssh_evidence",
        )

        self.assertEqual(len(results), 1)

        payload = results[0]

        self.assertEqual(payload["indicator"], "192.0.2.10")
        self.assertEqual(payload["indicator_type"], "ip")
        self.assertEqual(payload["category"], "post_access_evidence")
        self.assertEqual(payload["source"], "ssh_evidence")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["confidence"], "medium")
        self.assertEqual(payload["finding"]["artifact_type"], "system_info")
        self.assertEqual(
            payload["finding"]["data"]["hostname"],
            "LAB-PC",
        )
        self.assertIsInstance(payload["limitations"], list)

    def test_analyze_lab_evidence_timestamp_is_utc(self):
        evidence_file = self.test_dir / "system.log"
        evidence_file.write_text(
            "System started",
            encoding="utf-8",
        )

        results = analyze_lab_evidence(
            artifact_path=evidence_file,
            artifact_type="system_log",
            indicator="192.0.2.10",
            indicator_type="ip",
            source_tool="ssh_evidence",
        )

        timestamp = results[0]["collected_at_utc"]
        parsed_time = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

        self.assertEqual(
            parsed_time.utcoffset().total_seconds(),
            0,
        )

    def test_analyze_lab_evidence_rejects_empty_indicator(self):
        evidence_file = self.test_dir / "system.log"
        evidence_file.write_text("System started", encoding="utf-8")

        with self.assertRaises(ValueError):
            analyze_lab_evidence(
                artifact_path=evidence_file,
                artifact_type="system_log",
                indicator="",
                indicator_type="ip",
                source_tool="ssh_evidence",
            )

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_json_file(self):
        evidence_file = self.test_dir / "system_info.json"
        evidence_file.write_text(
            json.dumps({"hostname": "LAB-PC", "os": "Windows"}),
            encoding="utf-8",
        )

        result = parse_lab_evidence_file(evidence_file)

        self.assertEqual(result["file_type"], ".json")
        self.assertEqual(result["data"]["hostname"], "LAB-PC")

    def test_parse_csv_file(self):
        evidence_file = self.test_dir / "processes.csv"
        evidence_file.write_text(
            "name,pid\nexplorer.exe,100\n",
            encoding="utf-8",
        )

        result = parse_lab_evidence_file(evidence_file)

        self.assertEqual(result["file_type"], ".csv")
        self.assertEqual(result["data"][0]["name"], "explorer.exe")

    def test_parse_text_file(self):
        evidence_file = self.test_dir / "system.log"
        evidence_file.write_text(
            "System started\nNetwork connected\n",
            encoding="utf-8",
        )

        result = parse_lab_evidence_file(evidence_file)

        self.assertEqual(
            result["data"],
            ["System started", "Network connected"],
        )

    def test_missing_file(self):
        evidence_file = self.test_dir / "missing.json"

        with self.assertRaises(ValueError):
            parse_lab_evidence_file(evidence_file)

    def test_unsupported_file_format(self):
        evidence_file = self.test_dir / "sample.exe"
        evidence_file.write_text("test", encoding="utf-8")

        with self.assertRaises(ValueError):
            parse_lab_evidence_file(evidence_file)

    def test_invalid_json_file(self):
        evidence_file = self.test_dir / "invalid.json"
        evidence_file.write_text("{invalid json}", encoding="utf-8")

        with self.assertRaises(ValueError):
            parse_lab_evidence_file(evidence_file)


if __name__ == "__main__":
    unittest.main()
