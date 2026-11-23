
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from tracecase.network.pcap_parser import (
    MAX_FILE_SIZE,
    MAX_OUTPUT_SIZE,
    analyze_pcap,
    parse_pcap_file,
)


class FakeProcess:
    """A simple fake TShark process for unit tests."""

    def __init__(self, returncode=0):
        self.returncode = returncode

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


class TestPcapAnalyzer(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp_dir.name)

        self.capture_file = self.folder / "sample.pcap"
        self.capture_file.write_bytes(b"offline test fixture")

        self.tshark_file = self.folder / "tshark.exe"
        self.tshark_file.touch()

        self.patch_tshark = patch(
            "tracecase.network.pcap_parser.TSHARK_PATH",
            self.tshark_file,
        )
        self.patch_tshark.start()

    def tearDown(self):
        self.patch_tshark.stop()
        self.temp_dir.cleanup()

    def mock_tshark(self, mock_popen, output="", returncode=0):
        """Prepare a fake TShark process and its output."""

        def start_process(command, stdout, stderr, shell):
            if isinstance(output, str):
                stdout.write(output.encode("utf-8"))
            else:
                stdout.write(output)

            return FakeProcess(returncode)

        mock_popen.side_effect = start_process

    @patch("tracecase.network.pcap_parser.subprocess.Popen")
    def test_analyze_pcap_returns_finding_payload(self, mock_popen):
        output = (
            "1\t1700000000.0\t192.0.2.10\t"
            "\t198.51.100.20\t\tTCP\tTest packet\n"
        )
        self.mock_tshark(mock_popen, output)

        results = analyze_pcap(
            artifact_path=self.capture_file,
            indicator="192.0.2.10",
            indicator_type="ip",
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

    @patch("tracecase.network.pcap_parser.subprocess.Popen")
    def test_analyze_pcap_timestamp_is_utc(self, mock_popen):
        self.mock_tshark(mock_popen)

        results = analyze_pcap(
            artifact_path=self.capture_file,
            indicator="192.0.2.10",
            indicator_type="ip",
        )

        timestamp = results[0]["collected_at_utc"]
        parsed_time = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

        self.assertEqual(
            parsed_time.utcoffset().total_seconds(),
            0,
        )

    def test_analyze_pcap_rejects_empty_indicator(self):
        with self.assertRaises(ValueError):
            analyze_pcap(
                artifact_path=self.capture_file,
                indicator="",
                indicator_type="ip",
            )

    def test_analyze_pcap_rejects_empty_indicator_type(self):
        with self.assertRaises(ValueError):
            analyze_pcap(
                artifact_path=self.capture_file,
                indicator="192.0.2.10",
                indicator_type="",
            )

    @patch("tracecase.network.pcap_parser.subprocess.Popen")
    def test_parse_pcap_output(self, mock_popen):
        output = (
            "1\t1700000000.0\t192.0.2.10\t"
            "\t198.51.100.20\t\tTCP\tTest packet\n"
        )
        self.mock_tshark(mock_popen, output)

        results = parse_pcap_file(self.capture_file)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["frame_number"], "1")
        self.assertEqual(results[0]["source"], "192.0.2.10")
        self.assertEqual(results[0]["destination"], "198.51.100.20")
        self.assertEqual(results[0]["protocol"], "TCP")

    def test_missing_file(self):
        missing_file = self.folder / "missing.pcap"

        with self.assertRaisesRegex(ValueError, "does not exist"):
            parse_pcap_file(missing_file)

    def test_unsupported_file_format(self):
        wrong_file = self.folder / "sample.txt"
        wrong_file.write_text("test", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "Unsupported"):
            parse_pcap_file(wrong_file)

    @patch("tracecase.network.pcap_parser.subprocess.Popen")
    def test_tshark_error(self, mock_popen):
        self.mock_tshark(mock_popen, returncode=1)

        with self.assertRaisesRegex(ValueError, "could not read"):
            parse_pcap_file(self.capture_file)

    def test_file_size_limit(self):
        large_file = self.folder / "large.pcap"

        with large_file.open("wb") as file:
            file.truncate(MAX_FILE_SIZE + 1)

        with self.assertRaisesRegex(ValueError, "exceeds"):
            parse_pcap_file(large_file)

    def test_missing_tshark_executable(self):
        missing_tshark = self.folder / "missing_tshark.exe"

        with patch(
            "tracecase.network.pcap_parser.TSHARK_PATH",
            missing_tshark,
        ):
            with self.assertRaisesRegex(ValueError, "not found"):
                parse_pcap_file(self.capture_file)

    @patch("tracecase.network.pcap_parser.subprocess.Popen")
    @patch("tracecase.network.pcap_parser.time.sleep")
    @patch("tracecase.network.pcap_parser.time.monotonic")
    def test_tshark_timeout(
        self,
        mock_monotonic,
        mock_sleep,
        mock_popen,
    ):
        process = FakeProcess(returncode=None)
        mock_popen.return_value = process
        mock_monotonic.side_effect = [0, 31]

        with self.assertRaisesRegex(ValueError, "timed out"):
            parse_pcap_file(self.capture_file)

        self.assertEqual(process.returncode, -15)

    @patch("tracecase.network.pcap_parser.subprocess.Popen")
    def test_tshark_os_error(self, mock_popen):
        mock_popen.side_effect = OSError("Execution failed")

        with self.assertRaisesRegex(ValueError, "Unable to execute"):
            parse_pcap_file(self.capture_file)

    @patch("tracecase.network.pcap_parser.subprocess.Popen")
    def test_invalid_output_row_is_ignored(self, mock_popen):
        self.mock_tshark(mock_popen, "invalid output row\n")

        results = parse_pcap_file(self.capture_file)

        self.assertEqual(results, [])

    @patch("tracecase.network.pcap_parser.subprocess.Popen")
    def test_oversized_tshark_output_is_rejected(self, mock_popen):
        process = FakeProcess(returncode=None)

        def start_process(command, stdout, stderr, shell):
            stdout.write(b"A" * (MAX_OUTPUT_SIZE + 1))
            return process

        mock_popen.side_effect = start_process

        with self.assertRaisesRegex(ValueError, "output exceeds"):
            parse_pcap_file(self.capture_file)

        self.assertEqual(process.returncode, -15)


if __name__ == "__main__":
    unittest.main()
