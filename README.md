# 🛡️ Cybersecurity Log Analyzer

A Python-based cybersecurity monitoring project designed to analyze authentication logs, detect suspicious login activity, assess IP address risk, and manage security alerts through an interactive SOC dashboard.

This project was developed as a hands-on learning experience focused on **Python programming, defensive cybersecurity, log analysis, and security monitoring**.

## 📸 SOC Dashboard

![Cybersecurity SOC Dashboard](screenshots/dashboard.png)

## 🚀 Features

- **Security Log Analysis:** Parses authentication logs and identifies failed login attempts.
- **Brute Force Detection:** Detects repeated failed login attempts within a configurable time window.
- **IP Risk Assessment:** Assigns behavior-based risk levels and scores to suspicious IP addresses.
- **Interactive SOC Dashboard:** Visualizes security events using Streamlit.
- **Automatic Monitoring:** Supports configurable refresh intervals of 5, 10, 30, and 60 seconds.
- **Security Alerts:** Displays suspicious activity requiring investigation.
- **Alert Acknowledgement:** Allows an analyst to mark alerts as reviewed.
- **SQLite Database:** Stores security alerts and acknowledgement status persistently.
- **Security Reports:** Exports alert reports in JSON and risk assessment data in CSV.
- **Automated Testing:** Includes 21 unit tests.

## 🛠️ Technologies

- Python
- Streamlit
- Pandas
- SQLite
- Git & GitHub
- Python unittest

## 📂 Project Structure

```text
cybersecurity-log-analyzer/
├── main.py
├── detector.py
├── threat_intelligence.py
├── report_export.py
├── dashboard.py
├── database.py
├── security.log
├── screenshots/
│   └── dashboard.png
├── README.md
└── ...
```

## ⚙️ Installation

**1. Clone the repository**

```bash
git clone https://github.com/y7aseer/cybersecurity-log-analyzer.git
cd cybersecurity-log-analyzer
```

**2. Install dependencies**

```bash
python -m pip install streamlit pandas
```

**3. Launch the SOC Dashboard**

```bash
python -m streamlit run dashboard.py
```

The dashboard will open in your browser.

## 🔍 Example Security Log

The analyzer supports log entries formatted as follows:

```text
2026-10-08 15:00:00 | FAILED | 192.168.1.200
2026-10-08 15:00:10 | FAILED | 192.168.1.200
2026-10-08 15:00:20 | FAILED | 192.168.1.200
```

Repeated failed login attempts within a short time window can trigger a potential brute-force alert.

## 🚨 Security Alert Workflow

1. Read authentication log entries.
2. Identify failed login attempts.
3. Analyze suspicious patterns.
4. Generate security alerts.
5. Store detected alerts in SQLite.
6. Display alerts in the SOC dashboard.
7. Allow the analyst to acknowledge reviewed alerts.
8. Preserve alert status after restarting the application.

## 🧪 Running Tests

Run the automated test suite:

```bash
python -m unittest discover -v
```

The project includes 21 unit tests covering its core security analysis functionality.

## 🔐 Security Notes

This project is intended for educational and defensive cybersecurity purposes.

- The detection system uses log-based rules and behavioral heuristics.
- IP risk scores are estimates, not verified external threat intelligence.
- The dashboard monitors supported local or uploaded log data rather than collecting live network traffic.
- SQLite data is stored locally.
- The project is not intended to replace a production SIEM platform.

## 🎯 Learning Objectives

This project demonstrates practical experience with:

- Python software development
- Authentication log analysis
- Brute-force attack detection
- Defensive security monitoring
- Alert investigation workflows
- Database integration
- Data visualization
- Automated software testing

## 👨‍💻 Author

Developed by [y7aseer](https://github.com/y7aseer) as a personal cybersecurity learning project.

## 📄 License

No license has been specified for this repository.