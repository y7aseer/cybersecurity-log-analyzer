
import json
import pandas as pd


RISK_COLUMNS = [
    "IP Address",
    "Failed Attempts",
    "Risk Level",
    "Risk Score",
    "Reason"
]


def export_alerts_json(alerts):
    """Convert security alerts into JSON."""
    return json.dumps(
        alerts,
        indent=4,
        ensure_ascii=False
    )


def export_risk_csv(risk_data):
    """Convert IP risk assessments into CSV."""
    dataframe = pd.DataFrame(
        risk_data,
        columns=RISK_COLUMNS
    )

    return dataframe.to_csv(index=False)
