
import hashlib
import tempfile
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from main import read_security_logs, analyze_logs
from threat_intelligence import assess_ip_risk
from report_export import export_alerts_json, export_risk_csv
from database import (
    init_database,
    save_alert,
    acknowledge_alert,
    get_all_alerts,
    get_alert_counts,
)


# ==========================================
# Dashboard Configuration
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
# Initialize SQLite
# ==========================================

init_database()


# ==========================================
# Session Settings
# ==========================================

if "monitoring_enabled" not in st.session_state:
    st.session_state.monitoring_enabled = True

if "refresh_seconds" not in st.session_state:
    st.session_state.refresh_seconds = 5


# ==========================================
# Helper Functions
# ==========================================

def get_alert_id(alert, source_id):
    """
    Create a stable unique identifier for an alert.
    """

    parts = [
        source_id,
        str(alert.get("ip_address", "")),
        str(alert.get("attack_type", "")),
        str(alert.get("first_attempt", "")),
        str(alert.get("last_attempt", "")),
        str(alert.get("failed_attempts", "")),
    ]

    raw_id = "|".join(parts)

    return hashlib.sha256(
        raw_id.encode("utf-8")
    ).hexdigest()


def load_security_data(uploaded_file):
    """
    Load local security.log or an uploaded log file.
    """

    if uploaded_file is None:
        return read_security_logs(LOG_FILE)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir) / "uploaded.log"

        temp_path.write_bytes(
            uploaded_file.getvalue()
        )

        return read_security_logs(temp_path)


def register_alerts(alerts, source_id):
    """
    Save detected alerts to SQLite.
    Existing acknowledged alerts are not reset.
    """

    new_count = 0

    for alert in alerts:
        alert_id = get_alert_id(alert, source_id)

        if save_alert(alert_id, alert):
            new_count += 1

    return new_count


def get_history_dataframe(saved_alerts):
    """
    Prepare saved alerts for the history table.
    """

    columns = [
        "Detected At",
        "IP Address",
        "Attack Type",
        "Failed Attempts",
        "Severity",
        "Status",
        "Acknowledged At",
    ]

    rows = []

    for alert in saved_alerts:
        rows.append(
            {
                "Detected At": alert["detected_at"],
                "IP Address": alert["ip_address"],
                "Attack Type": alert["attack_type"],
                "Failed Attempts": alert["failed_attempts"],
                "Severity": alert["severity"],
                "Status": alert["status"],
                "Acknowledged At": (
                    alert["acknowledged_at"] or ""
                ),
            }
        )

    return pd.DataFrame(rows, columns=columns)


# ==========================================
# Persistent Security Alert Center
# ==========================================

def show_saved_alerts():

    saved_alerts = get_all_alerts()
    counts = get_alert_counts()

    st.divider()
    st.subheader("Persistent Security Alert Center")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "New Alerts",
        counts["new"],
    )

    col2.metric(
        "Acknowledged Alerts",
        counts["acknowledged"],
    )

    col3.metric(
        "Total Saved Alerts",
        counts["total"],
    )

    new_alerts = [
        alert
        for alert in saved_alerts
        if alert["status"] == "New"
    ]

    if new_alerts:

        st.error(
            f"{len(new_alerts)} security alert(s) "
            "require investigation."
        )

        for alert in new_alerts:

            with st.container(border=True):

                st.markdown(
                    f"**Potential Attack — "
                    f"{alert['ip_address']}**"
                )

                st.write(
                    f"Attack Type: {alert['attack_type']}"
                )

                st.write(
                    f"Failed Attempts: "
                    f"{alert['failed_attempts']}"
                )

                st.write(
                    f"Severity: {alert['severity']}"
                )

                st.write(
                    f"Detected At: {alert['detected_at']}"
                )

                if st.button(
                    "Acknowledge Alert",
                    key=f"ack_{alert['id']}",
                ):

                    acknowledge_alert(alert["id"])

                    st.rerun(scope="fragment")

    else:

        st.success(
            "No unreviewed security alerts."
        )

    # Persistent Alert History

    st.divider()
    st.subheader("Persistent Alert History")

    history_df = get_history_dataframe(
        saved_alerts
    )

    if not history_df.empty:

        st.dataframe(
            history_df,
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info(
            "No saved security alerts yet."
        )

    st.caption(
        "Alerts and acknowledgement status "
        "are stored in SQLite."
    )


# ==========================================
# Sidebar
# ==========================================

st.title("Cybersecurity SOC Dashboard")

st.caption(
    "Security Monitoring | Threat Detection | SQLite"
)

st.sidebar.header("Dashboard Controls")

uploaded_file = st.sidebar.file_uploader(
    "Upload Security Log",
    type=["log", "txt"],
)

monitoring_enabled = st.sidebar.toggle(
    "Automatic Monitoring",
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
        "Use security.log for continuously changing logs."
    )

if monitoring_enabled:

    st.sidebar.success(
        f"Monitoring Active — Every "
        f"{refresh_seconds} seconds"
    )

else:

    st.sidebar.warning(
        "Monitoring Paused"
    )


# ==========================================
# Automatic Refresh
# ==========================================

refresh_interval = (
    f"{refresh_seconds}s"
    if monitoring_enabled
    else None
)


# ==========================================
# Main Security Monitor
# ==========================================

@st.fragment(run_every=refresh_interval)
def security_monitor():

    if not monitoring_enabled:

        st.warning(
            "Monitoring paused. "
            "Saved alerts remain available."
        )

        show_saved_alerts()
        return

    # Read Security Logs

    try:

        failed_logins = load_security_data(
            uploaded_file
        )

    except (OSError, UnicodeError, ValueError) as error:

        st.error(
            f"Unable to read security logs: {error}"
        )

        show_saved_alerts()
        return

    # Detect Attacks

    alerts = analyze_logs(
        failed_logins
    )

    if uploaded_file is None:

        source_id = "local:security.log"

    else:

        file_hash = hashlib.sha256(
            uploaded_file.getvalue()
        ).hexdigest()

        source_id = f"upload:{file_hash}"

    newly_saved = register_alerts(
        alerts,
        source_id,
    )

    st.success(
        f"Monitoring Active — "
        f"Every {refresh_seconds} seconds"
    )

    st.caption(
        "Last checked: "
        + datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )

    if newly_saved > 0:

        st.error(
            f"{newly_saved} new security "
            "alert(s) saved to SQLite!"
        )

    # Persistent Alerts

    show_saved_alerts()

    # ======================================
    # Security Overview
    # ======================================

    st.divider()
    st.subheader("Security Overview")

    ip_options = [
        "All IPs"
    ] + sorted(
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
            alert
            for alert in alerts
            if alert["ip_address"] == selected_ip
        ]

    total_failed = sum(
        len(times)
        for times in filtered_logins.values()
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Failed Login Attempts",
        total_failed,
    )

    col2.metric(
        "IP Addresses",
        len(filtered_logins),
    )

    col3.metric(
        "Current Security Alerts",
        len(filtered_alerts),
    )

    # ======================================
    # IP Risk Assessment
    # ======================================

    st.divider()
    st.subheader("IP Risk Assessment")

    risk_data = []

    for ip, timestamps in filtered_logins.items():

        assessment = assess_ip_risk(
            timestamps
        )

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

        st.info(
            "No IP risk data available."
        )

    st.caption(
        "Risk scores are based on log behavior, "
        "not external threat intelligence."
    )

    # ======================================
    # Detected Security Alerts
    # ======================================

    st.divider()
    st.subheader("Detected Security Alerts")

    if filtered_alerts:

        st.dataframe(
            pd.DataFrame(
                filtered_alerts
            ),
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.success(
            "No suspicious activity detected."
        )

    # ======================================
    # Export Reports
    # ======================================

    st.divider()
    st.subheader("Export Security Reports")

    col_json, col_csv = st.columns(2)

    with col_json:

        st.download_button(
            label="Download JSON Report",
            data=export_alerts_json(
                filtered_alerts
            ),
            file_name="security_report.json",
            mime="application/json",
            use_container_width=True,
        )

    with col_csv:

        st.download_button(
            label="Download CSV Risk Report",
            data=export_risk_csv(
                risk_df.to_dict(
                    orient="records"
                )
            ),
            file_name="security_risk_report.csv",
            mime="text/csv",
            use_container_width=True,
        )


# ==========================================
# Run Dashboard
# ==========================================

security_monitor()

st.divider()

st.caption(
    "Cybersecurity Log Analyzer | "
    "Python + Streamlit + SQLite"
)
