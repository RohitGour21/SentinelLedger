import os
import sqlite3
import threading
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCHEMA_PATH = os.path.join(_PROJECT_ROOT, "database", "schema.sql")


def _database_path():
    return os.getenv(
        "DATABASE_PATH",
        os.path.join(_PROJECT_ROOT, "sentinel_ledger.db")
    )


# Return TIMESTAMP columns as datetime objects (as PyMySQL did), so the
# existing code that calls .strftime() on created_at keeps working.
sqlite3.register_converter(
    "TIMESTAMP",
    lambda value: datetime.fromisoformat(value.decode("utf-8"))
)


class _Cursor(sqlite3.Cursor):
    """sqlite3 cursor usable in a 'with' block, like PyMySQL's cursor."""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False


class _Connection(sqlite3.Connection):
    def cursor(self, factory=_Cursor):
        return super().cursor(factory)


def _dict_row(cursor, row):
    return {
        column[0]: value
        for column, value in zip(cursor.description, row)
    }


_init_lock = threading.Lock()
_initialized_path = None


def _connect():
    connection = sqlite3.connect(
        _database_path(),
        timeout=30,
        detect_types=sqlite3.PARSE_DECLTYPES,
        factory=_Connection
    )
    connection.row_factory = _dict_row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _create_initial_admin():
    """Optional: create the first Admin from environment variables.

    Needed on hosts without a shell (e.g. Render free tier) where
    create_admin.py cannot be run. Does nothing unless all three
    variables are set and no user exists yet.
    """
    username = os.getenv("INITIAL_ADMIN_USERNAME", "").strip()
    email = os.getenv("INITIAL_ADMIN_EMAIL", "").strip()
    password = os.getenv("INITIAL_ADMIN_PASSWORD", "")

    if not (username and email and password):
        print("INITIAL_ADMIN: skipped - set INITIAL_ADMIN_USERNAME, "
              "INITIAL_ADMIN_EMAIL and INITIAL_ADMIN_PASSWORD "
              f"(username set: {bool(username)}, email set: "
              f"{bool(email)}, password set: {bool(password)})",
              flush=True)
        return

    if len(password) < 12:
        print("INITIAL_ADMIN_PASSWORD must be at least 12 characters; "
              "initial Admin not created.", flush=True)
        return

    connection = _connect()
    try:
        total = connection.execute(
            "SELECT COUNT(*) AS total FROM users"
        ).fetchone()["total"]
    finally:
        connection.close()

    if total > 0:
        print("INITIAL_ADMIN: skipped - users already exist.", flush=True)
        return

    from app.services.auth_service import register_user
    success, message = register_user(username, email, password, role_id=1)
    print(f"INITIAL_ADMIN: created username '{username}'"
          if success else f"INITIAL_ADMIN: failed - {message}", flush=True)


def init_db():
    """Create tables and reference data if they do not exist."""
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as schema_file:
        schema = schema_file.read()

    connection = _connect()
    try:
        connection.executescript(schema)
        connection.commit()
    finally:
        connection.close()


def get_db_connection():
    global _initialized_path

    path = _database_path()
    if _initialized_path != path:
        with _init_lock:
            if _initialized_path != path:
                init_db()
                _initialized_path = path
                _create_initial_admin()

    return _connect()
