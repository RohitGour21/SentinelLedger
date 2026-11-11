
from getpass import getpass

from app.db import get_db_connection
from app.services.auth_service import register_user


def main():
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM users")
            total_users = cursor.fetchone()["total"]
    finally:
        connection.close()

    if total_users > 0:
        print("Setup stopped: a user already exists.")
        print("No new Admin account was created.")
        return

    print("Create the initial SentinelLedger Admin account")
    print("Role: Admin (role_id = 1)")
    print()

    username = input("Enter username: ").strip()
    email = input("Enter email: ").strip()
    password = getpass("Enter password: ")
    confirm_password = getpass("Confirm password: ")

    if not username or not email or not password:
        print("Error: All fields are required.")
        return

    if len(password) < 12:
        print("Error: Use a password with at least 12 characters.")
        return

    if password != confirm_password:
        print("Error: Passwords do not match.")
        return

    success, message = register_user(
        username=username,
        email=email,
        password=password,
        role_id=1
    )

    print(message)


if __name__ == "__main__":
    main()
