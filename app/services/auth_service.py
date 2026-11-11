
import sqlite3

from werkzeug.security import generate_password_hash, check_password_hash
from app.db import get_db_connection


def register_user(username, email, password, role_id=1):
    password_hash = generate_password_hash(password)

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO users
                    (username, email, password_hash, role_id, is_active)
                VALUES (?, ?, ?, ?, 1)
                """,
                (username, email, password_hash, role_id)
            )

        connection.commit()
        return True, "User registered successfully."

    except Exception as error:
        connection.rollback()

        if (
            isinstance(error, sqlite3.IntegrityError)
            and "UNIQUE" in str(error)
        ):
            return False, "Username or email already exists."

        raise

    finally:
        connection.close()


def authenticate_user(username, password):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT u.user_id, u.username, u.email,
                       u.password_hash, u.role_id, u.is_active,
                       r.role_name
                FROM users AS u
                JOIN roles AS r ON u.role_id = r.role_id
                WHERE u.username = ?
                """,
                (username,)
            )

            user = cursor.fetchone()

        if not user:
            return None

        if not user["is_active"]:
            return None

        if not check_password_hash(user["password_hash"], password):
            return None

        user.pop("password_hash", None)
        return user

    finally:
        connection.close()
