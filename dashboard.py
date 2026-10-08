
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from main import read_security_logs, analyze_logs
from threat_intelligence import assess_ip_risk
from report_export import export_alerts_json, export_risk_csv


BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "security.log"

st.set_page_config(
    page_title="Cybersecurity SOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.stApp {
    background-color: #0b1220;
    color: #e2e8f0;
}
h1, h2, h3 {
    color: #38bdf8 !important;
}
div[data-testid="stMetric"] {
    background: #172338;
    border: 1px solid #263b55;
    border-radius: 12px;
    padding: 18px;
}
div[data-testid="stMetricValue"] {
    color: #38bdf8;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Cybersecurity SOC Dashboard")
st.caption("Security Monitoring | Threat Detection | Risk Scoring")

st.sidebar.header("⚙️ Dashboard Controls")

uploaded_file = st.sidebar.file_uploader(
    "Upload Security Log",
    type=["log", "txt"],
    max_upload_size=10
)

try:
    if uploaded_file is not None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir) / "uploaded.log"
            temp_path.write_bytes(uploaded_file.getvalue())
            failed_logins = read_security_logs(temp_path)

        st.sidebar.success("Log uploaded successfully!")
    else:
        failed_logins = read_security_logs(LOG_FILE)

except (OSError, UnicodeError) as error:
    st.error(f"Unable to read log file: {error}")
    st.stop()

alerts = analyze_logs(failed_logins)

ip_options = ["All IPs"] + sorted(failed_logins.keys())

selected_ip = st.sidebar.selectbox(
    "Filter by IP",
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

st.divider()
st.subheader("📊 Security Overview")

total_failed = sum(
    len(times) for times in filtered_logins.values()
)

col1, col2, col3 = st.columns(3)

col1.metric("Failed Login Attempts", total_failed)
col2.metric("IP Addresses", len(filtered_logins))
col3.metric("Security Alerts", len(filtered_alerts))

st.divider()
st.subheader("📈 Failed Login Attempts by IP")

chart_data = pd.DataFrame([
    {
        "IP Address": ip,
        "Failed Attempts": len(times)
    }
    for ip, times in filtered_logins.items()
])

if not chart_data.empty:
    st.bar_chart(chart_data.set_index("IP Address"))
else:
    st.info("No failed logins detected.")

st.divider()
st.subheader("🕒 Failed Login Timeline")

timeline_rows = [
    {"Time": timestamp, "IP": ip}
    for ip, times in filtered_logins.items()
    for timestamp in times
]

if timeline_rows:
    timeline_df = pd.DataFrame(timeline_rows)
    timeline_df["Minute"] = timeline_df["Time"].dt.floor("min")

    timeline_counts = (
        timeline_df.groupby("Minute")
        .size()
        .rename("Failed Attempts")
    )

    st.line_chart(timeline_counts)
else:
    st.info("No timeline data available.")

st.divider()
st.subheader("🧠 Threat Intelligence & Risk Scoring")

risk_data = []

for ip, timestamps in filtered_logins.items():
    assessment = assess_ip_risk(timestamps)

    risk_data.append({
        "IP Address": ip,
        "Failed Attempts": len(timestamps),
        "Risk Level": assessment["risk_level"],
        "Risk Score": assessment["risk_score"],
        "Reason": assessment["reason"]
    })

risk_columns = [
    "IP Address",
    "Failed Attempts",
    "Risk Level",
    "Risk Score",
    "Reason"
]

risk_df = pd.DataFrame(risk_data, columns=risk_columns)

if not risk_df.empty:
    risk_df = risk_df.sort_values(
        "Risk Score",
        ascending=False
    )

    st.dataframe(
        risk_df,
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("No IP addresses to assess.")

st.caption(
    "Risk scores are behavior-based estimates, "
    "not external threat intelligence reputation scores."
)

st.divider()
st.subheader("🚨 Security Alerts")

if filtered_alerts:
    st.dataframe(
        pd.DataFrame(filtered_alerts),
        use_container_width=True
    )
else:
    st.success("No suspicious activity detected.")

st.divider()
st.subheader("📥 Export Security Reports")

col_json, col_csv = st.columns(2)

with col_json:
    st.download_button(
        label="📄 Download JSON Report",
        data=export_alerts_json(filtered_alerts),
        file_name="security_report.json",
        mime="application/json",
        use_container_width=True
    )

with col_csv:
    st.download_button(
        label="📊 Download CSV Risk Report",
        data=export_risk_csv(
            risk_df.to_dict(orient="records")
        ),
        file_name="security_risk_report.csv",
        mime="text/csv",
        use_container_width=True
    )

st.divider()
st.caption(
    "Cybersecurity Log Analyzer | Python + Streamlit"
)
