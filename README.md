# 🛡️ Cybersecurity Log Analyzer

**A Python-Based Security Monitoring & Threat Detection System**

A cybersecurity project built with Python, Streamlit, and SQLite to analyze authentication logs, detect suspicious login attempts, assess IP address risks, and manage security alerts through an interactive Security Operations Center (SOC) dashboard.

Developed as a personal hands-on cybersecurity project to practice defensive security, Python programming, log analysis, and security monitoring.

## 🚀 Live Demo

**Try the Cybersecurity SOC Dashboard directly in your browser:**

### 🌐 [Launch Live SOC Dashboard](https://y7aseer-cybersecurity.streamlit.app/)

No installation required.

**GitHub Repository:** [Cybersecurity Log Analyzer](https://github.com/y7aseer/cybersecurity-log-analyzer)

## 📸 Dashboard Preview

![Cybersecurity SOC Dashboard](screenshots/dashboard.png)

## ✨ Key Features

### 🔍 Security Log Analysis
- Reads and processes authentication log files.
- Extracts timestamps, login status, and IP addresses.
- Identifies failed login attempts and suspicious activity.

### 🚨 Brute Force Attack Detection
- Detects repeated failed login attempts from the same IP address.
- Uses time-window-based detection logic.
- Generates alerts for suspicious authentication patterns.

### 🧠 IP Risk Assessment
- Evaluates suspicious IP addresses using behavioral indicators.
- Assigns risk scores and severity levels.
- Helps prioritize potentially malicious activity.

### 📊 Interactive SOC Dashboard
- Built using Streamlit.
- Displays security monitoring metrics and visualizations.
- Supports uploading and analyzing log files.
- Provides IP filtering and security event analysis.

### 🔄 Automatic Monitoring
- Supports automatic refresh intervals of 5, 10, 30, and 60 seconds.
- Allows monitoring to be paused.
- Updates dashboard information as new log activity is processed.

### 🛡️ Security Alert Management
- Displays detected security alerts.
- Tracks new and acknowledged alerts.
- Allows analysts to acknowledge reviewed alerts.
- Provides a persistent alert history using SQLite.

### 💾 SQLite Database Integration
- Stores detected security alerts in a local SQLite database.
- Tracks alert status and acknowledgement timestamps.
- Prevents duplicate alert records.
- Preserves alert status across local application restarts.

### 📁 Report Export
- Exports security alerts in JSON format.
- Exports IP risk assessment results in CSV format.
- Supports further analysis and reporting.

### 🧪 Automated Testing
- Includes 21 unit tests.
- Uses Python's built-in `unittest` framework.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Core application and security analysis |
| Streamlit | Interactive SOC dashboard |
| Pandas | Data processing and reporting |
| SQLite | Security alert storage |
| Unittest | Automated testing |
| Git & GitHub | Version control and project hosting |
| Streamlit Community Cloud | Live application deployment |

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
├── requirements.txt
├── README.md
├── screenshots/
│   └── dashboard.png
└── ...
```

### Main Components

- **main.py:** Reads and analyzes security logs.
- **detector.py:** Detects potential brute-force attacks.
- **threat_intelligence.py:** Calculates behavior-based IP risk scores.
- **report_export.py:** Generates JSON and CSV reports.
- **dashboard.py:** Provides the interactive SOC monitoring interface.
- **database.py:** Manages SQLite security alerts and acknowledgement status.

## ⚙️ Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/y7aseer/cybersecurity-log-analyzer.git
cd cybersecurity-log-analyzer
```

### 2. Install Dependencies

Make sure Python is installed, then run:

```bash
python -m pip install -r requirements.txt
```

### 3. Run the SOC Dashboard

```bash
python -m streamlit run dashboard.py
```

The dashboard will be available locally at:

```text
http://localhost:8501
```

Alternatively, use the [Live Demo](https://y7aseer-cybersecurity.streamlit.app/) without installing anything.

## 🔎 Example Security Logs

The application processes authentication logs using the following format:

```text
2026-10-08 15:00:00 | FAILED | 192.168.1.100
2026-10-08 15:00:10 | FAILED | 192.168.1.100
2026-10-08 15:00:20 | FAILED | 192.168.1.100
2026-10-08 15:01:00 | FAILED | 192.168.1.200
```

Multiple failed login attempts from the same IP address within a short period can indicate a potential brute-force attack.

## 🚨 Security Monitoring Workflow

1. Load authentication logs.
2. Parse timestamps, login status, and IP addresses.
3. Identify failed authentication attempts.
4. Detect suspicious login patterns.
5. Assess IP address risk levels.
6. Generate security alerts.
7. Store alerts in SQLite.
8. Display alerts in the SOC dashboard.
9. Acknowledge reviewed alerts.
10. Export security reports when needed.

## 🧪 Running Unit Tests

Run the automated test suite using:

```bash
python -m unittest discover -v
```

The project includes 21 unit tests for its core analysis functionality.

## ☁️ Cloud Deployment

The SOC dashboard is deployed using **Streamlit Community Cloud**.

**Live Application:**

https://y7aseer-cybersecurity.streamlit.app/

The cloud-hosted application is intended for demonstration and educational use.

**Important:** SQLite storage on Streamlit Community Cloud is not guaranteed to persist after application restarts or redeployments. Visitors may also share the same alert database. Use synthetic security logs only and avoid uploading sensitive production data.

## 🔐 Security Considerations

- This project is designed for educational and defensive cybersecurity purposes.
- Detection is based on authentication log patterns and predefined rules.
- IP risk scores are behavior-based estimates, not verified external threat intelligence.
- The application is not a production SIEM system.
- The dashboard does not perform live network packet capture.
- Security logs used for public demonstrations should contain synthetic data only.

## 🎯 Skills Demonstrated

- Python programming
- Cybersecurity log analysis
- Brute-force attack detection
- Threat detection fundamentals
- Security monitoring and alert management
- SOC dashboard development
- SQLite database integration
- Data visualization
- Automated testing
- Git and GitHub
- Cloud application deployment

## 👨‍💻 Author

**GitHub:** [@y7aseer](https://github.com/y7aseer)

**Project:** [Cybersecurity Log Analyzer](https://github.com/y7aseer/cybersecurity-log-analyzer)

**Live Demo:** [Cybersecurity SOC Dashboard](https://y7aseer-cybersecurity.streamlit.app/)

---

*Developed as a personal cybersecurity learning project to strengthen practical skills in Python development, defensive security, and security operations.*