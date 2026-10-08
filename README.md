# Cybersecurity Log Analyzer

A Python-based security monitoring tool that analyzes authentication logs and detects potentially suspicious login activity.

## Features

- Reads authentication events from a log file.
- Identifies failed login attempts by IP address.
- Detects potential brute-force attacks using a sliding time window.
- Generates security alerts.
- Exports detected alerts to a JSON report.

## Technologies

- Python 3
- JSON
- Python Standard Library
- Git and GitHub

## Detection Logic

The tool generates an alert when an IP address has three or more failed login attempts within 60 seconds.

This behavior may indicate a brute-force attempt but does not confirm an actual attack.

## How to Run

1. Install Python 3.
2. Clone the repository.
3. Open the project folder.
4. Run:

```bash
python main.py
```

## Project Files

- `main.py` — Main security log analysis script
- `security.log` — Sample authentication logs
- `security_report.json` — Generated security alert report

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes.

## Author

Cybersecurity Student | Python Developer