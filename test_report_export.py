
import csv
import io
import json
import unittest

from report_export import (
    export_alerts_json,
    export_risk_csv
)


class TestReportExport(unittest.TestCase):

    def test_json_export(self):
        alerts = [
            {
                "ip_address": "192.168.1.10",
                "severity": "HIGH"
            }
        ]

        result = export_alerts_json(alerts)
        data = json.loads(result)

        self.assertEqual(
            data[0]["ip_address"],
            "192.168.1.10"
        )

    def test_empty_json_export(self):
        result = export_alerts_json([])

        self.assertEqual(
            json.loads(result),
            []
        )

    def test_csv_export(self):
        risk_data = [
            {
                "IP Address": "192.168.1.10",
                "Failed Attempts": 3,
                "Risk Level": "HIGH",
                "Risk Score": 90,
                "Reason": "Rapid repeated failed logins"
            }
        ]

        result = export_risk_csv(risk_data)

        rows = list(csv.DictReader(io.StringIO(result)))

        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["Risk Level"],
            "HIGH"
        )

    def test_empty_csv_export(self):
        result = export_risk_csv([])

        rows = list(csv.DictReader(io.StringIO(result)))

        self.assertEqual(rows, [])

    def test_csv_columns(self):
        result = export_risk_csv([])

        reader = csv.DictReader(io.StringIO(result))

        self.assertEqual(
            reader.fieldnames,
            [
                "IP Address",
                "Failed Attempts",
                "Risk Level",
                "Risk Score",
                "Reason"
            ]
        )


if __name__ == "__main__":
    unittest.main()
