
import unittest
from pathlib import Path

from tracecase.network.nmap_parser import (
    parse_nmap_xml_file,
    parse_nmap_xml,
)
from datetime import datetime


class TestNmapParser(unittest.TestCase):

    def test_parse_nmap_xml_returns_finding_payload(self):
        artifact_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "nmap"
            / "sample_nmap.xml"
        )

        results = parse_nmap_xml(
            artifact_path=artifact_path,
            indicator="192.0.2.10",
            indicator_type="ip"
        )

        self.assertEqual(len(results), 1)

        payload = results[0]

        self.assertEqual(payload["indicator"], "192.0.2.10")
        self.assertEqual(payload["indicator_type"], "ip")
        self.assertEqual(payload["category"], "network_analysis")
        self.assertEqual(payload["source"], "nmap")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["confidence"], "medium")
        self.assertIsNone(payload["source_url"])

        self.assertEqual(payload["finding"]["artifact_type"], "nmap_xml")
        self.assertEqual(payload["finding"]["total_hosts"], 1)
        self.assertEqual(payload["finding"]["total_ports"], 2)

        self.assertIn("hosts", payload["finding"])
        self.assertIsInstance(payload["limitations"], list)

    def test_parse_nmap_xml_timestamp_is_utc(self):
        artifact_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "nmap"
            / "sample_nmap.xml"
        )

        results = parse_nmap_xml(
            artifact_path=artifact_path,
            indicator="192.0.2.10",
            indicator_type="ip"
        )

        timestamp = results[0]["collected_at_utc"]
        parsed_time = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

        self.assertEqual(parsed_time.utcoffset().total_seconds(), 0)

    def test_parse_nmap_xml_rejects_empty_indicator(self):
        artifact_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "nmap"
            / "sample_nmap.xml"
        )

        with self.assertRaises(ValueError):
            parse_nmap_xml(
                artifact_path=artifact_path,
                indicator="",
                indicator_type="ip"
            )


    def test_parse_nmap_xml_file(self):
        artifact_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "nmap"
            / "sample_nmap.xml"
        )

        results = parse_nmap_xml_file(artifact_path)

        self.assertEqual(len(results), 1)

        host = results[0]

        self.assertEqual(host["address"], "192.0.2.10")
        self.assertEqual(host["hostname"], "example.test")

        self.assertEqual(len(host["ports"]), 2)

        self.assertEqual(host["ports"][0]["port"], "80")
        self.assertEqual(host["ports"][0]["state"], "open")
        self.assertEqual(host["ports"][0]["service"], "http")

        self.assertEqual(host["ports"][1]["port"], "443")
        self.assertEqual(host["ports"][1]["state"], "closed")
        self.assertEqual(host["ports"][1]["service"], "https")

    def test_missing_file(self):
        artifact_path = Path("missing_nmap.xml")

        with self.assertRaises(ValueError):
            parse_nmap_xml_file(artifact_path)

    def test_invalid_xml(self):
        artifact_path = Path(__file__).parent / "invalid.xml"

        artifact_path.write_text(
            "<nmaprun>",
            encoding="utf-8"
        )

        try:
            with self.assertRaises(ValueError):
                parse_nmap_xml_file(artifact_path)
        finally:
            artifact_path.unlink()


if __name__ == "__main__":
    unittest.main()
