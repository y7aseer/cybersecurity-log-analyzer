# 🛡️ Cybersecurity Log Analyzer

### Python-Based Security Monitoring & Threat Detection System

A cybersecurity project developed using **Python and Streamlit** to analyze authentication logs, detect potential brute-force attacks, assess IP address risk levels, and visualize suspicious activity through an interactive Security Operations Center (SOC) dashboard.

## 📸 Dashboard Preview

![Cybersecurity SOC Dashboard](screenshots/dashboard.png)

## 🚀 Features

- **Security Log Analysis:** Parse authentication logs and identify failed login attempts.
- **Brute-Force Attack Detection:** Identify repeated failed login attempts within a specified time window.
- **IP Risk Assessment:** Assign risk levels and scores based on suspicious login behavior.
- **Interactive SOC Dashboard:** Display security metrics, charts, alerts, and risk assessments.
- **Failed Login Timeline:** Visualize authentication failures over time.
- **IP Address Filtering:** Investigate security activity for specific IP addresses.
- **Log File Upload:** Analyze custom `.log` and `.txt` files.
- **JSON Report Export:** Download detected security alerts in JSON format.
- **CSV Report Export:** Download IP risk assessments in CSV format.
- **Automated Testing:** Validate the analyzer with 21 unit tests.

## 🛠️ Technologies Used

- Python 3
- Streamlit
- Pandas
- Git & GitHub
- JSON & CSV
- Python unittest

## 📂 Project Structure

```text
cybersecurity-log-analyzer/
├── main.py
├── detector.py
├── dashboard.py
├── threat_intelligence.py
├── report_export.py
├── security.log
├── security_report.json
├── test_detector.py
├── test_main.py
├── test_threat_intelligence.py
├── test_report_export.py
├── requirements.txt
├── README.md
├── .gitignore
└── screenshots/
    └── dashboard.png
```

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/y7aseer/cybersecurity-log-analyzer.git
cd cybersecurity-log-analyzer
```

### 2. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

## ▶️ Run the SOC Dashboard

Start the Streamlit dashboard:

```bash
python -m streamlit run dashboard.py
```

Open the local URL displayed in your terminal:

http://localhost:8501

The dashboard provides an interactive interface for investigating authentication failures, security alerts, and IP risk levels.

## 🔍 Run the Log Analyzer

Run the command-line analyzer:

```bash
python main.py
```

The analyzer reads `security.log`, processes failed login attempts, detects potential brute-force attacks, and generates a JSON security report.

## 🧪 Automated Unit Tests

Run all tests using:

```bash
python -m unittest discover -v
```

The project includes **21 unit tests** covering:

- Brute-force attack detection
- Security log parsing
- Log validation
- IP risk assessment
- JSON report export
- CSV report export

## 📝 Supported Log Format

Example authentication log entries:

```text
2026-10-08 10:00:00 | FAILED | 192.168.1.10
2026-10-08 10:00:15 | FAILED | 192.168.1.10
2026-10-08 10:00:30 | FAILED | 192.168.1.10
2026-10-08 10:02:00 | SUCCESS | 10.0.0.5
```

Each log entry contains a timestamp, authentication status, and IP address.

## 🚨 Brute-Force Detection Logic

The system uses a sliding time window to detect suspicious repeated login failures.

**Default detection configuration:**

- Failed login threshold: 3 attempts
- Detection time window: 60 seconds
- Detection scope: Individual IP addresses

If an IP address generates at least three failed login attempts within 60 seconds, the system generates a potential brute-force alert.

## 🧠 IP Risk Scoring

The system evaluates IP risk based on failed login behavior.

| Risk Level | Description |
|---|---|
| LOW | 1–2 failed login attempts |
| MEDIUM | 3–4 failed attempts without rapid-attack detection |
| HIGH | 5 or more failed attempts, or rapid repeated failures |

Risk scores are heuristic behavioral estimates and do not represent external threat intelligence reputation scores.

## 📊 Security Report Export

### JSON Security Report

Includes information such as:

- Suspicious IP address
- Attack type
- Number of failed attempts
- First and last detected attempts
- Severity level

### CSV Risk Assessment Report

Includes:

- IP Address
- Failed Attempts
- Risk Level
- Risk Score
- Assessment Reason

## 🔐 Security Considerations

This project is intended for educational and defensive cybersecurity purposes.

Use synthetic or sanitized authentication logs. The dashboard is designed for local analysis and demonstration, not production security monitoring.

Detection alerts indicate potentially suspicious behavior and should be investigated before confirming an attack.

## 🔮 Future Improvements

- Additional security log formats
- Configurable detection rules
- Enhanced alert investigation
- Automated dashboard tests
- More advanced security visualizations

## 👨‍💻 Author

**GitHub:** [@y7aseer](https://github.com/y7aseer)

**Repository:** [Cybersecurity Log Analyzer](https://github.com/y7aseer/cybersecurity-log-analyzer)

---

⭐ *Built with Python and Streamlit as a cybersecurity portfolio project.*