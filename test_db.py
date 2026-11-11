from app.db import get_db_connection, _database_path

try:
    connection = get_db_connection()

    with connection.cursor() as cursor:
        cursor.execute("SELECT sqlite_version() AS version")
        print("SQLite connected successfully!")
        print("Database file:", _database_path())
        print("SQLite version:", cursor.fetchone()["version"])

    connection.close()

except Exception as error:
    print("Database connection failed:")
    print(error)
