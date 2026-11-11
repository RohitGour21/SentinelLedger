
import json
import hashlib
from app.db import get_db_connection

connection = get_db_connection()

try:
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT log_id, action, ip_address, details,
                   previous_hash, entry_hash, created_at
            FROM audit_logs
            WHERE log_id = 1
        """)
        log = cursor.fetchone()

    timestamp = log["created_at"].strftime("%Y-%m-%d %H:%M:%S.%f")

    log_data = {
        "action": log["action"],
        "ip_address": log["ip_address"],
        "details": log["details"],
        "previous_hash": log["previous_hash"],
        "created_at": timestamp
    }

    data_string = json.dumps(
        log_data,
        sort_keys=True,
        separators=(",", ":")
    )

    calculated_hash = hashlib.sha256(
        data_string.encode("utf-8")
    ).hexdigest()

    print("Timestamp:", repr(timestamp))
    print("JSON:", data_string)
    print("Stored hash:", log["entry_hash"])
    print("Calculated hash:", calculated_hash)
    print("Match:", calculated_hash == log["entry_hash"])

finally:
    connection.close()
