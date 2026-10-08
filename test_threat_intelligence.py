
import unittest
from datetime import datetime, timedelta

from threat_intelligence import assess_ip_risk


class TestThreatIntelligence(unittest.TestCase):

    def setUp(self):
        self.start = datetime(2026, 10, 8, 10, 0, 0)

    def test_no_attempts(self):
        result = assess_ip_risk([])
        self.assertEqual(result["risk_level"], "NONE")

    def test_low_risk(self):
        result = assess_ip_risk([self.start])
        self.assertEqual(result["risk_level"], "LOW")

    def test_medium_risk(self):
        timestamps = [
            self.start + timedelta(minutes=i * 2)
            for i in range(3)
        ]
        result = assess_ip_risk(timestamps)
        self.assertEqual(result["risk_level"], "MEDIUM")

    def test_high_risk_brute_force(self):
        timestamps = [
            self.start + timedelta(seconds=i * 10)
            for i in range(3)
        ]
        result = assess_ip_risk(timestamps)
        self.assertEqual(result["risk_level"], "HIGH")

    def test_high_risk_many_attempts(self):
        timestamps = [
            self.start + timedelta(minutes=i * 2)
            for i in range(5)
        ]
        result = assess_ip_risk(timestamps)
        self.assertEqual(result["risk_level"], "HIGH")


if __name__ == "__main__":
    unittest.main()
