
import tempfile
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from main import read_security_logs, analyze_logs
from threat_intelligence import assess_ip_risk
from report_export import export_alerts_json, export_risk_csv


# ==========================================
# Configuration
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
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
        background-color: #172338;
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

if "alert_history" not in st.session_state:
    st.session_state.alert_history = {}

if "monitoring_enabled" not in st.session_state:
    st.session_state.monitoring_enabled = True

if "refresh_seconds" not in st.session_state:
    st.session_state.refresh_seconds = 5


# ==========================================
# Helper Functions
# ==========================================

def get_alert_id(alert, source_id):
    parts = [
        source_id,
        str(alert.get("ip_address", "")),
        str(alert.get("attack_type", "")),
        str(alert.get("first_attempt", "")),
        str(alert.get("last_attempt", "")),
        str(alert.get("failed_attempts", "")),
    ]
    return "|".join(parts)


def load_security_data(uploaded_file):
    if uploaded_file is None:
        return read_security_logs(LOG_FILE)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir) / "uploaded.log"
        temp_path.write_bytes(uploaded_file.getvalue())
        return read_security_logs(temp_path)


def register_alerts(alerts, source_id):
    new_alert_count = 0

    for alert in alerts:
        alert_id = get_alert_id(alert, source_id)

        if alert_id not in st.session_state.alert_history:
            st.session_state.alert_history[alert_id] = {
                "ID": alert_id,
                "Detected At": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "IP Address": alert.get("ip_address", "Unknown"),
                "Attack Type": alert.get("attack_type", "Unknown"),
                "Failed Attempts": alert.get("failed_attempts", 0),
                "Severity": alert.get("severity", "Unknown"),
                "Status": "New",
                "Acknowledged At": "",
            }
            new_alert_count += 1

    return new_alert_count


def acknowledge_alert(alert_id):
    history = st.session_state.alert_history

    if alert_id in history:
        history[alert_id]["Status"] = "Acknowledged"
        history[alert_id]["Acknowledged At"] = (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )


def get_alert_dataframe():
    columns = [
        "Detected At",
        "IP Address",
        "Attack Type",
        "Failed Attempts",
        "Severity",
        "Status",
        "Acknowledged At",
    ]

    records = list(st.session_state.alert_history.values())

    if not records:
        return pd.DataFrame(columns=columns)

    return (
        pd.DataFrame(records)[columns]
        .sort_values("Detected At", ascending=False)
    )


# ==========================================
# Sidebar
# ==========================================

st.title("🛡️ Cybersecurity SOC Dashboard")

st.caption(
    "Security Monitoring | Threat Detection | Alert Management"
)

st.sidebar.header("⚙️ Dashboard Controls")

uploaded_file = st.sidebar.file_uploader(
    "Upload Security Log",
    type=["log", "txt"],
)

monitoring_enabled = st.sidebar.toggle(
    "🔄 Automatic Monitoring",
    key="monitoring_enabled",
)

refresh_seconds = st.sidebar.selectbox(
    "Refresh Interval (seconds)",
    options=[5, 10, 30, 60],
    key="refresh_seconds",
    disabled=not monitoring_enabled,
)

if uploaded_file is not None:
    st.sidebar.info(
        "Uploaded files are static snapshots. "
        "Use security.log to monitor live file changes."
    )

if monitoring_enabled:
    st.sidebar.success(
        f"🟢 Monitoring Active — Every {refresh_seconds}s"
    )
else:
    st.sidebar.warning("🟡 Monitoring Paused")


# ==========================================
# Dynamic Refresh Configuration
# ==========================================

# Streamlit fragments support a dynamic run_every
# value. None disables automatic reruns.

refresh_interval = (
    f"{refresh_seconds}s"
    if monitoring_enabled
    else None
)


# ==========================================
# Security Monitor
# ==========================================

@st.fragment(run_every=refresh_interval)
def security_monitor():

    if not monitoring_enabled:
        st.warning(
            "🟡 Monitoring paused. "
            "Automatic log checks are disabled."
        )
        return

    try:
        failed_logins = load_security_data(uploaded_file)
    except (OSError, UnicodeError, ValueError) as error:
        st.error(f"Unable to read security logs: {error}")
        return

    alerts = analyze_logs(failed_logins)

    source_id = (
        f"upload:{uploaded_file.name}"
        if uploaded_file is not None
        else "local:security.log"
    )

    register_alerts(alerts, source_id)

    st.success(
        f"🟢 Monitoring active — Refresh every "
        f"{refresh_seconds} seconds"
    )

    st.caption(
        "Last checked: "
        + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    # ======================================
    # Alert Center
    # ======================================

    history = st.session_state.alert_history

    new_alerts = [
        item for item in history.values()
        if item["Status"] == "New"
    ]

    acknowledged_alerts = [
        item for item in history.values()
        if item["Status"] == "Acknowledged"
    ]

    st.divider()
    st.subheader("🚨 Security Alert Center")

    col1, col2, col3 = st.columns(3)

    col1.metric("New Alerts", len(new_alerts))
    col2.metric(
        "Acknowledged Alerts",
        len(acknowledged_alerts),
    )
    col3.metric("Total Recorded Alerts", len(history))

    if new_alerts:
        st.error(
            f"🚨 {len(new_alerts)} security alert(s) "
            "require investigation."
        )

        for item in reversed(new_alerts):
            with st.container(border=True):
                st.markdown(
                    f"**🚨 Potential Attack — "
                    f"{item['IP Address']}**"
                )

                st.write(
                    f"Attack Type: {item['Attack Type']}"
                )

                st.write(
                    f"Failed Attempts: "
                    f"{item['Failed Attempts']}"
                )

                st.write(
                    f"Severity: {item['Severity']}"
                )

                st.write(
                    f"Detected At: {item['Detected At']}"
                )

                if st.button(
                    "✅ Acknowledge Alert",
                    key=f"ack_{item['ID']}",
                ):
                    acknowledge_alert(item["ID"])
                    st.rerun(scope="fragment")

    else:
        st.success(
            "✅ No unreviewed security alerts."
        )

    # ======================================
    # Security Overview
    # ======================================

    st.divider()
    st.subheader("📊 Security Overview")

    ip_options = ["All IPs"] + sorted(
        failed_logins.keys()
    )

    selected_ip = st.selectbox(
        "Filter by IP Address",
        options=ip_options,
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
            alert for alert in alerts
            if alert["ip_address"] == selected_ip
        ]

    total_failed = sum(
        len(times)
        for times in filtered_logins.values()
    )

    overview1, overview2, overview3 = st.columns(3)

    overview1.metric(
        "Failed Login Attempts",
        total_failed,
    )

    overview2.metric(
        "IP Addresses",
        len(filtered_logins),
    )

    overview3.metric(
        "Current Security Alerts",
        len(filtered_alerts),
    )

    # ======================================
    # Failed Login Chart
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
            pd.to_datetime(
                timeline_df["Time"]
            ).dt.floor("min")
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
    # Risk Assessment
    # ======================================

    st.divider()
    st.subheader("🧠 IP Risk Assessment")

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
        st.info("No IP risk data available.")

    st.caption(
        "Risk scores are based on log behavior, "
        "not external IP reputation."
    )

    # ======================================
    # Detected Alerts
    # ======================================

    st.divider()
    st.subheader("🔎 Detected Security Alerts")

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

    history_df = get_alert_dataframe()

    if not history_df.empty:
        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No security alerts recorded yet.")

    st.caption(
        "Alert history is stored in the current "
        "Streamlit session only."
    )

    # ======================================
    # Export Reports
    # ======================================

    st.divider()
    st.subheader("📥 Export Security Reports")

    col_json, col_csv = st.columns(2)

    with col_json:
        st.download_button(
            label="📄 Download JSON Report",
            data=export_alerts_json(
                filtered_alerts
            ),
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


security_monitor()

st.divider()

st.caption(
    "Cybersecurity Log Analyzer | Python + Streamlit"
)
