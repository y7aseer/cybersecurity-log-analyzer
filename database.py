
import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).resolve().parent / "alerts.db"


def get_connection():
    connection = sqlite3.connect(
        DB_PATH,
        timeout=10,
    )
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    """Create the alerts table if it does not exist."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                detected_at TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New',
                acknowledged_at TEXT
            )
            """
        )


def save_alert(alert_id, alert):
    """Insert an alert only if it is not already saved."""
    detected_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO alerts (
                id,
                detected_at,
                ip_address,
                attack_type,
                failed_attempts,
                severity,
                status,
                acknowledged_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'New', NULL)
            """,
            (
                alert_id,
                detected_at,
                str(alert.get("ip_address", "Unknown")),
                str(alert.get("attack_type", "Unknown")),
                int(alert.get("failed_attempts", 0)),
                str(alert.get("severity", "Unknown")),
            ),
        )

        return cursor.rowcount > 0


def acknowledge_alert(alert_id):
    """Mark an existing new alert as acknowledged."""
    acknowledged_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE alerts
            SET status = 'Acknowledged',
                acknowledged_at = ?
            WHERE id = ?
              AND status = 'New'
            """,
            (acknowledged_at, alert_id),
        )

        return cursor.rowcount > 0


def get_all_alerts():
    """Return all saved alerts, newest first."""
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                detected_at,
                ip_address,
                attack_type,
                failed_attempts,
                severity,
                status,
                acknowledged_at
            FROM alerts
            ORDER BY detected_at DESC, rowid DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]


def get_alert_counts():
    """Count new, acknowledged, and total alerts."""
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(
                    CASE WHEN status = 'New'
                    THEN 1 ELSE 0 END
                ) AS new_count,
                SUM(
                    CASE WHEN status = 'Acknowledged'
                    THEN 1 ELSE 0 END
                ) AS acknowledged_count
            FROM alerts
            """
        ).fetchone()

    return {
        "total": row["total"] or 0,
        "new": row["new_count"] or 0,
        "acknowledged": row["acknowledged_count"] or 0,
    }


if __name__ == "__main__":
    init_database()
    print(f"Database initialized: {DB_PATH}")
