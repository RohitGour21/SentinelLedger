
from app.db import get_db_connection


def detect_excessive_api_requests(ip_address):
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
                ("Excessive API Requests",)
            )

            rule = cursor.fetchone()

            if not rule:
                return False

            rule_id = rule["rule_id"]
            threshold = int(rule["threshold_value"])
            time_window = int(rule["time_window_minutes"])

            # Count API requests within the configured window
            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM audit_logs
                WHERE action = ?
                  AND ip_address = ?
                  AND created_at >=
                      datetime('now', '-' || ? || ' minutes')
                """,
                ("API_REQUEST", ip_address, time_window)
            )

            request_count = cursor.fetchone()["total"]

            # Find the latest API request audit log for this IP
            cursor.execute(
                """
                SELECT log_id
                FROM audit_logs
                WHERE action = ?
                AND ip_address = ?
                ORDER BY log_id DESC
                LIMIT 1
                """,
                ("API_REQUEST", ip_address)
            )

            latest_log = cursor.fetchone()
            log_id = latest_log["log_id"] if latest_log else None


            if request_count < threshold:
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
                    "EXCESSIVE_API_REQUESTS",
                    f"%IP: {ip_address}%"
                )
            )

            if cursor.fetchone():
                return False

            # Create the event with its rule ID and linked audit log
            cursor.execute(
                """
                INSERT INTO security_events
                    (rule_id, log_id, event_type, severity, description, status)
                VALUES (?, ?, ?, ?, ?, 'OPEN')
                """,
                (
                    rule_id,
                    log_id,
                    "EXCESSIVE_API_REQUESTS",
                    "HIGH",
                    f"{threshold} or more API requests within "
                    f"{time_window} minute(s). IP: {ip_address}"
                )
            )

        connection.commit()
        return True

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
