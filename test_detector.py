
import unittest
from datetime import datetime, timedelta
from detector import detect_brute_force


class TestBruteForceDetector(unittest.TestCase):

    def setUp(self):
        self.start = datetime(2026, 10, 8, 10, 0, 0)

    def test_detects_attack(self):
        timestamps = [
            self.start,
            self.start + timedelta(seconds=15),
            self.start + timedelta(seconds=30)
        ]
        self.assertTrue(detect_brute_force(timestamps))

    def test_no_attack(self):
        timestamps = [
            self.start,
            self.start + timedelta(minutes=2),
            self.start + timedelta(minutes=4)
        ]
        self.assertFalse(detect_brute_force(timestamps))

    def test_empty_logs(self):
        self.assertFalse(detect_brute_force([]))

    def test_unordered_logs(self):
        timestamps = [
            self.start + timedelta(seconds=30),
            self.start,
            self.start + timedelta(seconds=15)
        ]
        self.assertTrue(detect_brute_force(timestamps))

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect_brute_force([self.start], threshold=0)


if __name__ == "__main__":
    unittest.main()
