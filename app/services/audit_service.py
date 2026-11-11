
import hashlib
import json
from datetime import datetime, timezone

from app.db import get_db_connection
from app.services.threat_detector import detect_repeated_failed_logins


def calculate_hash(log_data):
    data_string = json.dumps(
        log_data,
        sort_keys=True,
        separators=(",", ":")
    )
    return hashlib.sha256(data_string.encode("utf-8")).hexdigest()


def create_audit_log(action, ip_address, details=""):
    connection = get_db_connection()
    log_id = None

    try:
        # Prevent two processes from appending simultaneously:
        # BEGIN IMMEDIATE takes SQLite's write lock before the last hash
        # is read, and holds it until commit (waits up to the connection
        # timeout if another writer is appending).
        connection.execute("BEGIN IMMEDIATE")

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT entry_hash FROM audit_logs "
                "ORDER BY log_id DESC LIMIT 1"
            )
            last_log = cursor.fetchone()

            previous_hash = (
                last_log["entry_hash"] if last_log else "0" * 64
            )

            created_at = datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )

            log_data = {
                "action": action,
                "ip_address": ip_address,
                "details": details,
                "previous_hash": previous_hash,
                "created_at": created_at
            }

            entry_hash = calculate_hash(log_data)

            cursor.execute(
                """
                INSERT INTO audit_logs
                (action, ip_address, details,
                previous_hash, entry_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    action,
                    ip_address,
                    details,
                    previous_hash,
                    entry_hash,
                    created_at
                )
            )

            log_id = cursor.lastrowid
            connection.commit()

        # Run threat detection only AFTER the audit transaction is committed.
        if action == "LOGIN_FAILED":
            detect_repeated_failed_logins(ip_address)

        return log_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
