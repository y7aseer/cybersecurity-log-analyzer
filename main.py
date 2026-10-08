import json
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
import ipaddress

LOG_FILE = Path(__file__).parent / "security.log"
THRESHOLD = 3
TIME_WINDOW = timedelta(seconds=60)

failed_logins = defaultdict(list)

# Read the security log file
with open(LOG_FILE, "r", encoding="utf-8") as file:
    for line_number, line in enumerate(file, start=1):
        parts = line.strip().split(" | ")

        if len(parts) != 3:
            print(f"[WARNING] Invalid line: {line_number}")
            continue

        timestamp_text, status, ip = parts

        try:
            timestamp = datetime.strptime(
                timestamp_text, "%Y-%m-%d %H:%M:%S"
            )
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"[WARNING] Invalid data on line {line_number}")
            continue

        if status == "FAILED":
            failed_logins[ip].append(timestamp)
        elif status != "SUCCESS":
            print(f"[WARNING] Unknown status on line {line_number}")

print("=== Cybersecurity Log Analyzer ===")
print("Detection: 3 failed logins within 60 seconds")
print("----------------------------------")


security_alerts = []

for ip, timestamps in failed_logins.items():
    timestamps.sort()
    print(f"IP: {ip} | Total Failed Attempts: {len(timestamps)}")

    left = 0

    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > TIME_WINDOW:
            left += 1

        count = right - left + 1

        if count >= THRESHOLD:
            print("[ALERT] Possible Brute Force Attack!")
            print(f"  Suspicious IP: {ip}")
            print(f"  Attempts in window: {count}")

            security_alerts.append({
                "ip_address": ip,
                "attack_type": "Possible Brute Force",
                "failed_attempts": count,
                "first_attempt": timestamps[left].isoformat(),
                "last_attempt": timestamps[right].isoformat(),
                "severity": "HIGH"
            })

            break


print("----------------------------------")
print("Analysis completed successfully.")


# Save security alerts to JSON report
report_file = Path(__file__).parent / "security_report.json"

with open(report_file, "w", encoding="utf-8") as file:
    json.dump(security_alerts, file, indent=4)

print(f"[REPORT] Saved {len(security_alerts)} security alerts")
print(f"[REPORT] File: {report_file.name}")
