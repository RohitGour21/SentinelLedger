
from app.db import get_db_connection

try:
    connection = get_db_connection()

    with connection.cursor() as cursor:
        cursor.execute("SELECT role_id, role_name FROM roles")
        roles = cursor.fetchall()

        print("Connected to SentinelLedger!")
        print("Roles:", roles)

    connection.close()

except Exception as error:
    print("Connection failed:", error)
