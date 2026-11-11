
from app.db import get_db_connection


def get_all_users():
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT u.user_id, u.username, u.email,
                       u.role_id, r.role_name, u.is_active,
                       u.created_at
                FROM users AS u
                JOIN roles AS r ON u.role_id = r.role_id
                ORDER BY u.user_id
            """)

            return cursor.fetchall()

    finally:
        connection.close()


def get_all_roles():
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT role_id, role_name
                FROM roles
                ORDER BY role_id
            """)

            return cursor.fetchall()

    finally:
        connection.close()


def update_user_role(user_id, role_id):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT role_id FROM roles WHERE role_id = ?",
                (role_id,)
            )

            if not cursor.fetchone():
                return False, "Invalid role selected."

            cursor.execute(
                "UPDATE users SET role_id = ? WHERE user_id = ?",
                (role_id, user_id)
            )

            if cursor.rowcount == 0:
                cursor.execute(
                    "SELECT user_id FROM users WHERE user_id = ?",
                    (user_id,)
                )

                if not cursor.fetchone():
                    return False, "User not found."

        connection.commit()
        return True, "User role updated successfully."

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def update_user_status(user_id, is_active):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET is_active = ? WHERE user_id = ?",
                (is_active, user_id)
            )

            if cursor.rowcount == 0:
                cursor.execute(
                    "SELECT user_id FROM users WHERE user_id = ?",
                    (user_id,)
                )

                if not cursor.fetchone():
                    return False, "User not found."

        connection.commit()
        return True, "User status updated successfully."

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
