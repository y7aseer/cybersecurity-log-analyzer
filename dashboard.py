
import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from main import read_security_logs, analyze_logs


# Project paths
BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "security.log"


# Dashboard settings
st.set_page_config(
    page_title="Cybersecurity Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Cybersecurity Security Dashboard")
st.caption("Python-Based Security Log Monitoring Tool")

st.divider()


# Upload security logs
st.subheader("📁 Upload Security Log File")

uploaded_file = st.file_uploader(
    "Choose a security log file",
    type=["log", "txt"],
    max_upload_size=10
)

try:
    if uploaded_file is not None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / "uploaded.log"
            temp_path.write_bytes(uploaded_file.getvalue())
            failed_logins = read_security_logs(temp_path)

        st.success("Log file uploaded successfully!")
    else:
        failed_logins = read_security_logs(LOG_FILE)

except (OSError, UnicodeError) as error:
    st.error(f"Could not read security logs: {error}")
    st.stop()


# Analyze logs
alerts = analyze_logs(failed_logins)


# Interactive IP filter
st.divider()
st.subheader("🔎 Filter by IP Address")

ip_options = ["All IPs"] + sorted(failed_logins.keys())

selected_ip = st.selectbox(
    "Select an IP Address",
    ip_options
)

if selected_ip == "All IPs":
    filtered_logins = failed_logins
    filtered_alerts = alerts
else:
    filtered_logins = {
        selected_ip: failed_logins[selected_ip]
    }
    filtered_alerts = [
        alert for alert in alerts
        if alert["ip_address"] == selected_ip
    ]


# Security overview
total_failed = sum(
    len(timestamps)
    for timestamps in filtered_logins.values()
)

total_ips = len(filtered_logins)
total_alerts = len(filtered_alerts)

st.divider()
st.subheader("📊 Security Overview")

col1, col2, col3 = st.columns(3)

col1.metric("Failed Login Attempts", total_failed)
col2.metric("IP Addresses", total_ips)
col3.metric("Security Alerts", total_alerts)


# Failed attempts chart
st.divider()
st.subheader("📈 Failed Login Attempts by IP")

chart_data = pd.DataFrame([
    {
        "IP Address": ip,
        "Failed Attempts": len(timestamps)
    }
    for ip, timestamps in filtered_logins.items()
])

if not chart_data.empty:
    st.bar_chart(
        chart_data.set_index("IP Address")
    )
else:
    st.info("No failed login attempts found.")


# Security alerts
st.divider()
st.subheader("🚨 Security Alerts")

if filtered_alerts:
    alerts_df = pd.DataFrame(filtered_alerts)

    st.dataframe(
        alerts_df,
        use_container_width=True
    )
else:
    st.success("No suspicious activity detected.")


# Download JSON report
st.divider()
st.subheader("📥 Download Security Report")

report_json = json.dumps(
    filtered_alerts,
    indent=4,
    ensure_ascii=False
)

st.download_button(
    label="Download JSON Report",
    data=report_json,
    file_name="security_report.json",
    mime="application/json"
)


# Footer
st.divider()
st.caption(
    "Educational Cybersecurity Project | "
    "Developed with Python and Streamlit"
)
