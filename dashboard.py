
import tempfile
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st

from main import read_security_logs, analyze_logs
from threat_intelligence import assess_ip_risk
from report_export import export_alerts_json, export_risk_csv


# ==========================================
# Configuration
# ==========================================

BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "security.log"

st.set_page_config(
    page_title="Cybersecurity SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
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
    """,
    unsafe_allow_html=True,
)


# ==========================================
# Session State
# ==========================================

if "seen_alerts" not in st.session_state:
    st.session_state.seen_alerts = set()

if "alert_history" not in st.session_state:
    st.session_state.alert_history = []


# ==========================================
# Helper Functions
# ==========================================

def get_alert_id(alert):
    """Create a stable identifier for a detected alert."""
    return "|".join(
        [
            str(alert.get("ip_address", "")),
            str(alert.get("attack_type", "")),
            str(alert.get("first_attempt", "")),
            str(alert.get("last_attempt", "")),
            str(alert.get("failed_attempts", "")),
        ]
    )


def load_security_data(uploaded_file):
    """Read either the uploaded log or the local log file."""
    if uploaded_file is None:
        return read_security_logs(LOG_FILE)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir) / "uploaded.log"
        temp_path.write_bytes(uploaded_file.getvalue())
        return read_security_logs(temp_path)


def register_new_alerts(alerts):
    """Track newly discovered alerts without duplicating history."""
    new_alerts = []

    for alert in alerts:
        alert_id = get_alert_id(alert)

        if alert_id not in st.session_state.seen_alerts:
            st.session_state.seen_alerts.add(alert_id)

            history_entry = {
                "Detected At": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "IP Address": alert.get("ip_address"),
                "Attack Type": alert.get("attack_type"),
                "Failed Attempts": alert.get("failed_attempts"),
                "Severity": alert.get("severity"),
            }

            st.session_state.alert_history.append(history_entry)
            new_alerts.append(alert)

    return new_alerts


# ==========================================
# Sidebar
# ==========================================

st.title("🛡️ Cybersecurity SOC Dashboard")
st.caption(
    "Security Monitoring | Threat Detection | Real-Time Alerts"
)

st.sidebar.header("⚙️ Dashboard Controls")

uploaded_file = st.sidebar.file_uploader(
    "Upload Security Log",
    type=["log", "txt"],
    max_upload_size=10,
)

monitoring_enabled = st.sidebar.toggle(
    "🔄 Automatic Monitoring",
    value=True,
)

refresh_seconds = st.sidebar.selectbox(
    "Refresh Interval",
    options=[5, 10, 30, 60],
    index=0,
)

sound_enabled = st.sidebar.toggle(
    "🔊 Alert Sound",
    value=False,
)

if uploaded_file is not None:
    st.sidebar.info(
        "Monitoring uploaded file content. "
        "For continuously changing logs, use the local security.log."
    )

st.sidebar.divider()

if monitoring_enabled:
    st.sidebar.success(
        f"🟢 Monitoring Active — Every {refresh_seconds}s"
    )
else:
    st.sidebar.warning("🟡 Monitoring Paused")


# ==========================================
# Auto-Refreshing Dashboard
# ==========================================

@st.fragment(run_every=5)
def security_monitor():

    # Read data and analyze current events
    try:
        failed_logins = load_security_data(uploaded_file)
    except (OSError, UnicodeError) as error:
        st.error(f"Unable to read log file: {error}")
        return

    alerts = analyze_logs(failed_logins)

    # Register alerts only while monitoring is enabled
    if monitoring_enabled:
        new_alerts = register_new_alerts(alerts)
    else:
        new_alerts = []

    # ======================================
    # Monitoring Status
    # ======================================

    st.subheader("📡 Live Security Monitoring")

    if monitoring_enabled:
        st.success("🟢 Security monitoring is active.")
    else:
        st.warning("🟡 Security monitoring is paused.")

    st.caption(
        "Last dashboard check: "
        + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    # ======================================
    # New Security Alerts
    # ======================================

    st.subheader("🚨 Live Security Alerts")

    if new_alerts:
        for alert in new_alerts:
            ip = alert.get("ip_address", "Unknown")
            attempts = alert.get("failed_attempts", 0)

            st.error(
                f"🚨 POTENTIAL BRUTE-FORCE ATTACK! "
                f"IP: {ip} | Failed Attempts: {attempts}"
            )

        if sound_enabled:
            st.audio(
                "https://actions.google.com/sounds/v1/alarms/beep_short.ogg",
                autoplay=True,
            )

    elif alerts:
        st.warning(
            f"⚠️ {len(alerts)} existing security alert(s) "
            "detected in the current log."
        )
    else:
        st.success("✅ No suspicious activity detected.")

    # ======================================
    # IP Filter
    # ======================================

    ip_options = ["All IPs"] + sorted(failed_logins.keys())

    selected_ip = st.selectbox(
        "Filter by IP Address",
        ip_options,
        key="live_ip_filter",
    )

    if selected_ip == "All IPs":
        filtered_logins = failed_logins
        filtered_alerts = alerts
    else:
        filtered_logins = {
            selected_ip: failed_logins[selected_ip]
        }
        filtered_alerts = [
            alert
            for alert in alerts
            if alert["ip_address"] == selected_ip
        ]

    # ======================================
    # Security Overview
    # ======================================

    st.divider()
    st.subheader("📊 Security Overview")

    total_failed = sum(
        len(times) for times in filtered_logins.values()
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Failed Login Attempts", total_failed)
    col2.metric("IP Addresses", len(filtered_logins))
    col3.metric("Security Alerts", len(filtered_alerts))
    col4.metric(
        "Alert History",
        len(st.session_state.alert_history),
    )

    # ======================================
    # Failed Attempts Chart
    # ======================================

    st.divider()
    st.subheader("📈 Failed Login Attempts by IP")

    chart_data = pd.DataFrame(
        [
            {
                "IP Address": ip,
                "Failed Attempts": len(times),
            }
            for ip, times in filtered_logins.items()
        ]
    )

    if not chart_data.empty:
        st.bar_chart(
            chart_data.set_index("IP Address")
        )
    else:
        st.info("No failed login attempts found.")

    # ======================================
    # Timeline
    # ======================================

    st.divider()
    st.subheader("🕒 Failed Login Timeline")

    timeline_rows = [
        {"Time": timestamp, "IP": ip}
        for ip, times in filtered_logins.items()
        for timestamp in times
    ]

    if timeline_rows:
        timeline_df = pd.DataFrame(timeline_rows)

        timeline_df["Minute"] = (
            timeline_df["Time"].dt.floor("min")
        )

        timeline_counts = (
            timeline_df.groupby("Minute")
            .size()
            .rename("Failed Attempts")
        )

        st.line_chart(timeline_counts)
    else:
        st.info("No timeline data available.")

    # ======================================
    # Risk Scoring
    # ======================================

    st.divider()
    st.subheader("🧠 Threat Intelligence & Risk Scoring")

    risk_data = []

    for ip, timestamps in filtered_logins.items():
        assessment = assess_ip_risk(timestamps)

        risk_data.append(
            {
                "IP Address": ip,
                "Failed Attempts": len(timestamps),
                "Risk Level": assessment["risk_level"],
                "Risk Score": assessment["risk_score"],
                "Reason": assessment["reason"],
            }
        )

    risk_columns = [
        "IP Address",
        "Failed Attempts",
        "Risk Level",
        "Risk Score",
        "Reason",
    ]

    risk_df = pd.DataFrame(
        risk_data,
        columns=risk_columns,
    )

    if not risk_df.empty:
        risk_df = risk_df.sort_values(
            "Risk Score",
            ascending=False,
        )

        st.dataframe(
            risk_df,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No IP addresses to assess.")

    st.caption(
        "Risk scores are behavior-based estimates, "
        "not external IP reputation scores."
    )

    # ======================================
    # Current Security Alerts
    # ======================================

    st.divider()
    st.subheader("🚨 Current Security Alerts")

    if filtered_alerts:
        st.dataframe(
            pd.DataFrame(filtered_alerts),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.success("No suspicious activity detected.")

    # ======================================
    # Alert History
    # ======================================

    st.divider()
    st.subheader("📋 Security Alert History")

    if st.session_state.alert_history:
        history_df = pd.DataFrame(
            st.session_state.alert_history
        )

        st.dataframe(
            history_df.iloc[::-1],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No alerts recorded in this session.")

    # ======================================
    # Report Export
    # ======================================

    st.divider()
    st.subheader("📥 Export Security Reports")

    col_json, col_csv = st.columns(2)

    with col_json:
        st.download_button(
            label="📄 Download JSON Report",
            data=export_alerts_json(filtered_alerts),
            file_name="security_report.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_csv:
        st.download_button(
            label="📊 Download CSV Risk Report",
            data=export_risk_csv(
                risk_df.to_dict(orient="records")
            ),
            file_name="security_risk_report.csv",
            mime="text/csv",
            use_container_width=True,
        )


# Run monitoring fragment
security_monitor()

st.divider()
st.caption(
    "Cybersecurity Log Analyzer | Python + Streamlit"
)
