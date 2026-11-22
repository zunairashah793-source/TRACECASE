
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tracecase.network.pcap_parser import (
    parse_pcap_file,
    analyze_pcap,
)
from datetime import datetime

class TestPcapAnalyzer(unittest.TestCase):
    @patch("tracecase.network.pcap_parser.subprocess.run")
    def test_analyze_pcap_returns_finding_payload(self, mock_run):
        mock_run.return_value = SimpleNamespace(
            returncode=0,
            stdout=(
                "1\t1700000000.0\t192.0.2.10\t"
                "\t198.51.100.20\t\tTCP\tTest packet\n"
            )
        )

        results = analyze_pcap(
            artifact_path=self.capture_file,
            indicator="192.0.2.10",
            indicator_type="ip"
        )

        self.assertEqual(len(results), 1)

        payload = results[0]

        self.assertEqual(payload["indicator"], "192.0.2.10")
        self.assertEqual(payload["indicator_type"], "ip")
        self.assertEqual(payload["category"], "network_analysis")
        self.assertEqual(payload["source"], "tshark")
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["confidence"], "medium")
        self.assertEqual(payload["finding"]["total_packets"], 1)
        self.assertEqual(payload["finding"]["artifact_type"], "pcap")
        self.assertIsInstance(payload["limitations"], list)

    @patch("tracecase.network.pcap_parser.subprocess.run")
    def test_analyze_pcap_timestamp_is_utc(self, mock_run):
        mock_run.return_value = SimpleNamespace(
            returncode=0,
            stdout=""
        )

        results = analyze_pcap(
            artifact_path=self.capture_file,
            indicator="192.0.2.10",
            indicator_type="ip"
        )

        timestamp = results[0]["collected_at_utc"]
        parsed_time = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

        self.assertEqual(
            parsed_time.utcoffset().total_seconds(),
            0
        )

    def test_analyze_pcap_rejects_empty_indicator(self):
        with self.assertRaises(ValueError):
            analyze_pcap(
                artifact_path=self.capture_file,
                indicator="",
                indicator_type="ip"
            )

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp_dir.name)

        self.capture_file = self.folder / "sample.pcap"
        self.capture_file.write_bytes(b"offline test fixture")

        self.tshark_file = self.folder / "tshark.exe"
        self.tshark_file.touch()

        self.patch_tshark = patch(
            "tracecase.network.pcap_parser.TSHARK_PATH",
            self.tshark_file
        )
        self.patch_tshark.start()

    def tearDown(self):
        self.patch_tshark.stop()
        self.temp_dir.cleanup()

    @patch("tracecase.network.pcap_parser.subprocess.run")
    def test_parse_pcap_output(self, mock_run):

        mock_run.return_value = SimpleNamespace(
            returncode=0,
            stdout=(
                "1\t1700000000.0\t192.0.2.10\t"
                "\t198.51.100.20\t\tTCP\tTest packet\n"
            )
        )

        results = parse_pcap_file(self.capture_file)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["frame_number"], "1")
        self.assertEqual(results[0]["source"], "192.0.2.10")
        self.assertEqual(results[0]["destination"], "198.51.100.20")
        self.assertEqual(results[0]["protocol"], "TCP")

    def test_missing_file(self):
        missing_file = self.folder / "missing.pcap"

        with self.assertRaises(ValueError):
            parse_pcap_file(missing_file)

    def test_unsupported_file_format(self):
        wrong_file = self.folder / "sample.txt"
        wrong_file.write_text("test", encoding="utf-8")

        with self.assertRaises(ValueError):
            parse_pcap_file(wrong_file)

    @patch("tracecase.network.pcap_parser.subprocess.run")
    def test_tshark_error(self, mock_run):

        mock_run.return_value = SimpleNamespace(
            returncode=1,
            stdout="",
        )

        with self.assertRaises(ValueError):
            parse_pcap_file(self.capture_file)


if __name__ == "__main__":
    unittest.main()
