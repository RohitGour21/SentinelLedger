
from app.db import get_db_connection


def detect_repeated_failed_logins(ip_address):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            # Read the rule ID and configuration
            cursor.execute(
                """
                SELECT rule_id, threshold_value, time_window_minutes
                FROM security_rules
                WHERE rule_name = ?
                """,
                ("Repeated Failed Logins",)
            )

            rule = cursor.fetchone()

            if not rule:
                return False

            rule_id = rule["rule_id"]
            threshold = int(rule["threshold_value"])
            time_window = int(rule["time_window_minutes"])

            # Count failed logins from this IP
            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM audit_logs
                WHERE action = ?
                  AND ip_address = ?
                  AND created_at >=
                      datetime('now', '-' || ? || ' minutes')
                """,
                ("LOGIN_FAILED", ip_address, time_window)
            )

            failed_attempts = cursor.fetchone()["total"]

            # Find the latest failed-login audit log for this IP
            cursor.execute(
                """
                SELECT log_id
                FROM audit_logs
                WHERE action = ?
                AND ip_address = ?
                ORDER BY log_id DESC
                LIMIT 1
                """,
                ("LOGIN_FAILED", ip_address)
            )

            latest_log = cursor.fetchone()
            log_id = latest_log["log_id"] if latest_log else None


            if failed_attempts < threshold:
                return False

            # Avoid duplicate open events for the same IP
            cursor.execute(
                """
                SELECT event_id
                FROM security_events
                WHERE event_type = ?
                  AND status = 'OPEN'
                  AND description LIKE ?
                LIMIT 1
                """,
                (
                    "REPEATED_FAILED_LOGINS",
                    f"%IP: {ip_address}%"
                )
            )

            existing_event = cursor.fetchone()

            if existing_event:
                return False

            # Create the event with its rule ID and audit log ID
            cursor.execute(
                """
                INSERT INTO security_events
                    (rule_id, log_id, event_type, severity, description, status)
                VALUES (?, ?, ?, ?, ?, 'OPEN')
                """,
                (
                    rule_id,
                    log_id,
                    "REPEATED_FAILED_LOGINS",
                    "HIGH",
                    f"{threshold} or more failed login attempts "
                    f"within {time_window} minutes. IP: {ip_address}"
                )
            )


            connection.commit()
            return True

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
