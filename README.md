# 🛡️ Cybersecurity Log Analyzer

**Python-Based Security Monitoring & Threat Detection System**

A cybersecurity project built with Python and Streamlit to analyze authentication logs, detect potential brute-force attacks, assess IP risk levels, and visualize security events through an interactive Security Operations Center (SOC) dashboard.

## 📸 Dashboard Preview

![Cybersecurity SOC Dashboard](screenshots/dashboard.png)

## 🚀 Features

- **Security Log Analysis:** Parse authentication logs and identify failed login attempts.
- **Brute-Force Detection:** Detect suspicious repeated login failures within a configurable time window.
- **IP Risk Scoring:** Classify IP addresses as LOW, MEDIUM, or HIGH risk based on authentication failure patterns.
- **Interactive SOC Dashboard:** Monitor login statistics, suspicious IP addresses, and security alerts.
- **Failed Login Timeline:** Visualize failed authentication attempts over time.
- **IP Address Filtering:** Investigate individual IP addresses using interactive filters.
- **Log File Upload:** Upload and analyze `.log` and `.txt` files.
- **JSON Report Export:** Download detected security alerts.
- **CSV Risk Report Export:** Export IP risk assessments for analysis in Excel.
- **Automated Unit Testing:** Validate core functionality using Python's unittest framework.

## 🛠️ Technologies Used

- Python 3
- Streamlit
- Pandas
- Git & GitHub
- JSON & CSV
- unittest

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

**1. Clone the repository**

```bash
git clone https://github.com/y7aseer/cybersecurity-log-analyzer.git
cd cybersecurity-log-analyzer
```

**2. Install dependencies**

```bash
python -m pip install -r requirements.txt
```

## ▶️ Run the Dashboard

Start the Streamlit application:

```bash
python -m streamlit run dashboard.py
```

Open the local address shown in the terminal, usually:

http://localhost:8501

## 🔍 Run the Log Analyzer

To analyze the default log file from the command line:

```bash
python main.py
```

The analyzer reads `security.log`, detects suspicious login patterns, and generates `security_report.json`.

## 🧪 Automated Tests

Run all unit tests:

```bash
python -m unittest discover -v
```

The project includes **21 unit tests** covering:

- Brute-force detection
- Security log parsing
- Invalid log handling
- IP risk assessment
- JSON report generation
- CSV report generation

## 📝 Supported Log Format

The analyzer expects log entries in this format:

```text
2026-10-08 10:00:00 | FAILED | 192.168.1.10
2026-10-08 10:00:15 | FAILED | 192.168.1.10
2026-10-08 10:00:30 | FAILED | 192.168.1.10
2026-10-08 10:02:00 | SUCCESS | 10.0.0.5
```

Each entry contains a timestamp, authentication status, and IP address.

## 🚨 Brute-Force Detection

The detection algorithm uses a sliding time window to identify repeated authentication failures.

Default detection settings:

- **Threshold:** 3 failed login attempts
- **Time Window:** 60 seconds
- **Detection:** Potential brute-force activity from the same IP address

## 🧠 IP Risk Assessment

IP addresses are assigned heuristic risk scores based on failed login activity.

| Risk Level | Description |
|---|---|
| LOW | One or two failed login attempts |
| MEDIUM | Three or four failed attempts without rapid-attack detection |
| HIGH | Five or more failed attempts, or detected rapid repeated failures |

Risk scores are behavior-based estimates, not external IP reputation intelligence or definitive evidence of an attack.

## 📊 Security Reports

The application supports two report formats:

**JSON Report**

Contains detected security alerts, suspicious IP addresses, timestamps, and severity levels.

**CSV Risk Report**

Contains IP addresses, failed attempt counts, risk levels, risk scores, and assessment reasons.

## 🔐 Security Considerations

This project is designed for educational and defensive cybersecurity analysis.

- Use synthetic or appropriately sanitized log files.
- Avoid uploading sensitive production logs.
- The current dashboard is intended for local use and demonstration.
- Detection alerts require further investigation before confirming malicious activity.

## 🔮 Future Improvements

- Support additional log formats
- Configurable detection thresholds
- Enhanced log validation
- Automated dashboard testing
- Improved security event