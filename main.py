
import json
import ipaddress

from pathlib import Path
from datetime import datetime
from collections import defaultdict

from detector import find_brute_force_window


BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "security.log"
REPORT_FILE = BASE_DIR / "security_report.json"

THRESHOLD = 3
WINDOW_SECONDS = 60


def read_security_logs(file_path):
    failed_logins = defaultdict(list)

    with open(file_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            parts = line.strip().split(" | ")

            if len(parts) != 3:
                print(f"[WARNING] Invalid line: {line_number}")
                continue

            timestamp_text, status, ip = parts

            try:
                timestamp = datetime.strptime(
                    timestamp_text,
                    "%Y-%m-%d %H:%M:%S"
                )
                ipaddress.ip_address(ip)
            except ValueError:
                print(f"[WARNING] Invalid data on line {line_number}")
                continue

            if status == "FAILED":
                failed_logins[ip].append(timestamp)
            elif status != "SUCCESS":
                print(f"[WARNING] Unknown status on line {line_number}")

    return failed_logins


def analyze_logs(failed_logins):
    security_alerts = []

    print("=== Cybersecurity Log Analyzer ===")
    print("----------------------------------")

    for ip, timestamps in failed_logins.items():
        print(f"IP: {ip} | Total Failed Attempts: {len(timestamps)}")

        result = find_brute_force_window(
            timestamps,
            threshold=THRESHOLD,
            window_seconds=WINDOW_SECONDS
        )

        if result is not None:
            print("[ALERT] Possible Brute Force Attack!")
            print(f"  Suspicious IP: {ip}")
            print(f"  Attempts in window: {result['count']}")

            security_alerts.append({
                "ip_address": ip,
                "attack_type": "Possible Brute Force",
                "failed_attempts": result["count"],
                "first_attempt": result["first_attempt"].isoformat(),
                "last_attempt": result["last_attempt"].isoformat(),
                "severity": "HIGH"
            })

    return security_alerts


def save_report(alerts, file_path):
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print("----------------------------------")
    print(f"[REPORT] Saved {len(alerts)} security alerts")
    print(f"[REPORT] File: {file_path.name}")


def main():
    failed_logins = read_security_logs(LOG_FILE)
    alerts = analyze_logs(failed_logins)
    save_report(alerts, REPORT_FILE)
    print("Analysis completed successfully.")


if __name__ == "__main__":
    main()
