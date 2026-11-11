
from app.db import get_db_connection
from app.services.audit_service import calculate_hash


def verify_audit_chain():
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT log_id, action, ip_address, details,
                       previous_hash, entry_hash, created_at
                FROM audit_logs
                ORDER BY log_id ASC
            """)
            logs = cursor.fetchall()

        previous_hash = "0" * 64

        for log in logs:
            if log["previous_hash"] != previous_hash:
                return {
                    "valid": False,
                    "message": "Broken hash chain",
                    "log_id": log["log_id"]
                }

            timestamp = log["created_at"].strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )

            log_data = {
                "action": log["action"],
                "ip_address": log["ip_address"],
                "details": log["details"],
                "previous_hash": log["previous_hash"],
                "created_at": timestamp
            }

            expected_hash = calculate_hash(log_data)

            if expected_hash != log["entry_hash"]:
                return {
                    "valid": False,
                    "message": "Audit log hash mismatch",
                    "log_id": log["log_id"]
                }

            previous_hash = log["entry_hash"]

        return {
            "valid": True,
            "message": "Audit chain verified successfully",
            "total_logs": len(logs)
        }

    finally:
        connection.close()
