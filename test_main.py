
import unittest
import json
import tempfile

from pathlib import Path
from datetime import datetime

from main import read_security_logs, analyze_logs, save_report


class TestSecurityLogAnalyzer(unittest.TestCase):

    def create_log_file(self, content):
        """Create a temporary log file for testing."""
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)

        log_path = Path(temp.name) / "test_security.log"
        log_path.write_text(content, encoding="utf-8")

        return log_path

    def test_read_valid_logs(self):
        content = (
            "2026-10-08 10:00:00 | FAILED | 192.168.1.10\n"
            "2026-10-08 10:00:15 | FAILED | 192.168.1.10\n"
        )

        log_path = self.create_log_file(content)
        result = read_security_logs(log_path)

        self.assertEqual(len(result["192.168.1.10"]), 2)

    def test_successful_login_not_counted(self):
        content = (
            "2026-10-08 10:00:00 | SUCCESS | 192.168.1.20\n"
        )

        log_path = self.create_log_file(content)
        result = read_security_logs(log_path)

        self.assertEqual(len(result), 0)

    def test_invalid_log_ignored(self):
        content = (
            "INVALID LOG LINE\n"
            "2026-10-08 10:00:00 | FAILED | 192.168.1.10\n"
        )

        log_path = self.create_log_file(content)
        result = read_security_logs(log_path)

        self.assertEqual(len(result["192.168.1.10"]), 1)

    def test_invalid_ip_ignored(self):
        content = (
            "2026-10-08 10:00:00 | FAILED | invalid-ip\n"
        )

        log_path = self.create_log_file(content)
        result = read_security_logs(log_path)

        self.assertEqual(len(result), 0)

    def test_alert_generation(self):
        timestamps = [
            datetime(2026, 10, 8, 10, 0, 0),
            datetime(2026, 10, 8, 10, 0, 15),
            datetime(2026, 10, 8, 10, 0, 30)
        ]

        result = analyze_logs({
            "192.168.1.10": timestamps
        })

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["attack_type"],
            "Possible Brute Force"
        )
        self.assertEqual(result[0]["failed_attempts"], 3)

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as temp:
            report_path = Path(temp) / "test_report.json"

            alerts = [
                {
                    "ip_address": "192.168.1.10",
                    "attack_type": "Possible Brute Force",
                    "severity": "HIGH"
                }
            ]

            save_report(alerts, report_path)

            self.assertTrue(report_path.exists())

            with open(report_path, "r", encoding="utf-8") as file:
                data = json.load(file)

            self.assertEqual(len(data), 1)
            self.assertEqual(
                data[0]["severity"],
                "HIGH"
            )


if __name__ == "__main__":
    unittest.main()
