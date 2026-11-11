from app.services.hash_service import verify_audit_chain
from flask import Flask, render_template, request, redirect, url_for,session, flash
from app.db import get_db_connection
from app.services.audit_service import create_audit_log

from functools import wraps
from app.services.auth_service import authenticate_user

from app.services.user_service import (
    get_all_users,
    get_all_roles,
    update_user_role,
    update_user_status
)

from flask_wtf.csrf import CSRFProtect

import csv
import io
from flask import Response


from datetime import timedelta

from app.services.api_monitor import detect_excessive_api_requests

from app.services.threat_detector import detect_repeated_failed_logins

app = Flask(__name__)


import os

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY is missing. Add it to your .env file."
    )

# Session security settings
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Enable this when the application is served over HTTPS
app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
    "SESSION_COOKIE_SECURE", "False"
).lower() == "true"


csrf = CSRFProtect(app)



def role_required(*allowed_roles):
    def decorator(view_function):
        @wraps(view_function)
        def wrapped_view(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))

            if session.get("role_name") not in allowed_roles:
                ip_address = request.remote_addr or "unknown"

                username = session.get("username")
                role_name = session.get("role_name")

                # Record the unauthorized access in the audit log
                create_audit_log(
                    action="UNAUTHORIZED_ACCESS",
                    ip_address=ip_address,
                    details=(
                        f"User {username} "
                        f"(role: {role_name}) "
                        f"attempted to access {request.path}"
                    )
                )

                connection = get_db_connection()

                try:
                    with connection.cursor() as cursor:
                        # Read the rule configuration
                        cursor.execute(
                            """
                            SELECT rule_id,threshold_value, time_window_minutes
                            FROM security_rules
                            WHERE rule_name = ?
                            """,
                            ("Unauthorized Access",)
                        )

                        rule = cursor.fetchone()

                        if rule:
                            rule_id = rule["rule_id"]
                            threshold = int(rule["threshold_value"])
                            time_window = int(
                                rule["time_window_minutes"]
                            )

                            # Count recent unauthorized attempts
                            cursor.execute(
                                """
                                SELECT COUNT(*) AS total
                                FROM audit_logs
                                WHERE action = ?
                                  AND ip_address = ?
                                  AND created_at >=
                                      datetime('now', '-' || ? || ' minutes')
                                """,
                                (
                                    "UNAUTHORIZED_ACCESS",
                                    ip_address,
                                    time_window
                                )
                            )

                            attempt_count = cursor.fetchone()["total"]

                            cursor.execute(
                                """
                                SELECT log_id
                                FROM audit_logs
                                WHERE action = ?
                                AND ip_address = ?
                                ORDER BY log_id DESC
                                LIMIT 1
                                """,
                                ("UNAUTHORIZED_ACCESS", ip_address)
                            )

                            latest_log = cursor.fetchone()
                            log_id = latest_log["log_id"] if latest_log else None


                            if attempt_count >= threshold:
                                # Avoid duplicate open events
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
                                        "UNAUTHORIZED_ACCESS",
                                        f"%IP: {ip_address}%"
                                    )
                                )

                                if not cursor.fetchone():
                                    cursor.execute(
                                        """
                                        INSERT INTO security_events
                                            (rule_id, log_id, event_type, severity,
                                            description, status)
                                        VALUES (?, ?, ?, ?, ?, 'OPEN')
                                        """,
                                        (
                                            rule_id,
                                            log_id,
                                            "UNAUTHORIZED_ACCESS",
                                            "HIGH",
                                            f"{attempt_count} or more "
                                            f"unauthorized access attempts "
                                            f"within {time_window} minute(s). "
                                            f"User: {username}; "
                                            f"Path: {request.path}; "
                                            f"IP: {ip_address}"
                                        )
                                    )

                    connection.commit()

                except Exception:
                    connection.rollback()
                    raise

                finally:
                    connection.close()

                return (
                    "Access denied: You do not have permission "
                    "to access this page.",
                    403
                )

            return view_function(*args, **kwargs)

        return wrapped_view
    return decorator





@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Get the client's IP address
        ip_address = request.remote_addr or "unknown"

        user = authenticate_user(username, password)

        if user:
            # Record successful login
            create_audit_log(
                "LOGIN_SUCCESS",
                ip_address,
                f"Successful login for username: {username}"
            )

            session.clear()
            session.permanent = True
            session["user_id"] = user["user_id"]
            session["username"] = user["username"]
            session["role_id"] = user["role_id"]
            session["role_name"] = user["role_name"]

            return redirect(url_for("home"))

        # Record failed login
        create_audit_log(
            "LOGIN_FAILED",
            ip_address,
            f"Failed login attempt for username: {username}"
        )
        detect_repeated_failed_logins(ip_address)
        
        flash("Invalid username or password, or account inactive.")

    return render_template("login.html")



@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))




@app.route("/")
@role_required("Admin", "Security Analyst", "Viewer")

def home():
    create_audit_log(
        action="DASHBOARD_VIEW",
        ip_address=request.remote_addr or "127.0.0.1",
        details="Dashboard opened"
    )

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM audit_logs")
            total_logs = cursor.fetchone()["total"]

            cursor.execute(
                "SELECT COUNT(*) AS total FROM security_events "
                "WHERE status = 'OPEN'"
            )
            open_alerts = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) AS total FROM users")
            total_users = cursor.fetchone()["total"]

            # Count resolved security events
            cursor.execute("""
                SELECT COUNT(*) AS total
                FROM security_events
                WHERE status = 'RESOLVED'
            """)
            resolved_events = cursor.fetchone()["total"]

            # Count open high and critical alerts
            cursor.execute("""
                SELECT COUNT(*) AS total
                FROM security_events
                WHERE severity IN ('HIGH', 'CRITICAL')
                  AND status = 'OPEN'
            """)
            critical_alerts = cursor.fetchone()["total"]
            
            # Count open alerts by severity
            cursor.execute("""
                SELECT
                    SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) AS low_count,
                    SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_count,
                    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high_count,
                    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count
                FROM security_events
                WHERE status = 'OPEN'
            """)
            severity_counts = cursor.fetchone()

            low_alerts = severity_counts["low_count"] or 0
            medium_alerts = severity_counts["medium_count"] or 0
            high_alerts = severity_counts["high_count"] or 0
            critical_only_alerts = severity_counts["critical_count"] or 0


            # Fetch the 5 most recent security events
            cursor.execute("""
                SELECT
                    event_id,
                    event_type,
                    severity,
                    status,
                    description
                FROM security_events
                ORDER BY
                    CASE status
                        WHEN 'OPEN' THEN 1
                        WHEN 'RESOLVED' THEN 2
                        ELSE 3
                    END,
                    CASE severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END,
                    event_id DESC
                LIMIT 5
            """)
            recent_events = cursor.fetchall()
            # Count all security events by severity
            cursor.execute("""
                SELECT
                    SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) AS low_count,
                    SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_count,
                    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high_count,
                    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count
                FROM security_events
            """)
            event_severity_counts = cursor.fetchone()



        return render_template(
            "index.html",
            total_logs=total_logs,
            open_alerts=open_alerts,
            total_users=total_users,
            resolved_events=resolved_events,
            critical_alerts=critical_alerts,
            low_alerts=low_alerts,
            medium_alerts=medium_alerts,
            high_alerts=high_alerts,
            critical_only_alerts=critical_only_alerts,
            event_severity_counts=event_severity_counts,
            recent_events=recent_events
        )
    finally:
        connection.close()



@app.route("/logs/export")
@role_required("Admin", "Security Analyst", "Viewer")
def export_audit_logs():
    search_query = request.args.get("q", "").strip()
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    query = "SELECT * FROM audit_logs WHERE 1=1"
    parameters = []

    if search_query:
        query += """
            AND (
                action LIKE ?
                OR ip_address LIKE ?
                OR details LIKE ?
            )
        """
        pattern = f"%{search_query}%"
        parameters.extend([pattern, pattern, pattern])

    if start_date:
        query += " AND created_at >= ?"
        parameters.append(start_date)

    if end_date:
        query += " AND created_at < date(?, '+1 day')"
        parameters.append(end_date)

    query += " ORDER BY log_id DESC LIMIT 1000"

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(query, parameters)
            logs = cursor.fetchall()
    finally:
        connection.close()

    output = io.StringIO()
    writer = csv.writer(output)

    columns = [
        "log_id",
        "action",
        "ip_address",
        "details",
        "created_at",
        "previous_hash",
        "entry_hash"
    ]

    writer.writerow(columns)

    for log in logs:
        row = []
        for column in columns:
            value = log.get(column)

            if value is None:
                value = ""
            elif column == "created_at":
                value = value.strftime("%Y-%m-%d %H:%M:%S.%f")
            else:
                value = str(value)

            # Prevent spreadsheet formula injection
            if isinstance(value, str) and value.lstrip().startswith(
                ("=", "+", "-", "@")
            ):
                value = "'" + value

            row.append(value)

        writer.writerow(row)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=sentinel_audit_logs.csv"
        }
    )




@app.route("/verify")
@role_required("Admin", "Security Analyst")
def verify():
    result = verify_audit_chain()

    create_audit_log(
        action="AUDIT_CHAIN_VERIFICATION",
        ip_address=request.remote_addr or "127.0.0.1",
        details=f"Audit chain verification requested: {result['message']}"
    )

    return render_template(
        "verify.html",
        result=result
    )





@app.route("/logs")
@role_required("Admin", "Security Analyst", "Viewer")
def audit_logs():
    search_query = request.args.get("q", "").strip()
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    per_page = 50
    offset = (page - 1) * per_page

    conditions = []
    parameters = []

    if search_query:
        conditions.append(
            "(action LIKE ? OR ip_address LIKE ? OR details LIKE ?)"
        )
        pattern = f"%{search_query}%"
        parameters.extend([pattern, pattern, pattern])

    if start_date:
        conditions.append("created_at >= ?")
        parameters.append(start_date)

    if end_date:
        conditions.append(
            "created_at < date(?, '+1 day')"
        )
        parameters.append(end_date)

    where_clause = (
        " WHERE " + " AND ".join(conditions)
        if conditions else ""
    )

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) AS total FROM audit_logs" + where_clause,
                parameters
            )
            total_logs = cursor.fetchone()["total"]

            cursor.execute(
                "SELECT * FROM audit_logs"
                + where_clause
                + " ORDER BY log_id DESC LIMIT ? OFFSET ?",
                parameters + [per_page, offset]
            )
            logs = cursor.fetchall()

        total_pages = max(1, (total_logs + per_page - 1) // per_page)

        return render_template(
            "audit_logs.html",
            logs=logs,
            search_query=search_query,
            start_date=start_date,
            end_date=end_date,
            page=page,
            total_pages=total_pages,
            total_logs=total_logs
        )

    finally:
        connection.close()





@app.route("/events")
@role_required("Admin", "Security Analyst", "Viewer")
def security_events():
    status = request.args.get("status", "ALL").upper()
    severity = request.args.get("severity", "ALL").upper()
    search_query = request.args.get("q", "").strip()

    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    per_page = 10
    offset = (page - 1) * per_page

    if status not in {"ALL", "OPEN", "OTHER"}:
        status = "ALL"

    if severity not in {"ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        severity = "ALL"

    conditions = ["1=1"]
    parameters = []

    if status == "OPEN":
        conditions.append("status = ?")
        parameters.append("OPEN")
    elif status == "OTHER":
        conditions.append("status <> ?")
        parameters.append("OPEN")

    if severity != "ALL":
        conditions.append("severity = ?")
        parameters.append(severity)

    if search_query:
        conditions.append(
            "(event_type LIKE ? OR description LIKE ?)"
        )
        search_pattern = f"%{search_query}%"
        parameters.extend([search_pattern, search_pattern])

    where_clause = " AND ".join(conditions)

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT COUNT(*) AS total "
                f"FROM security_events WHERE {where_clause}",
                parameters
            )
            total_events = cursor.fetchone()["total"]

            total_pages = max(
                1, (total_events + per_page - 1) // per_page
            )
            page = min(page, total_pages)
            offset = (page - 1) * per_page

            cursor.execute(
                f"SELECT * FROM security_events "
                f"WHERE {where_clause} "
                f"ORDER BY detected_at DESC, event_id DESC "
                f"LIMIT ? OFFSET ?",
                parameters + [per_page, offset]
            )
            events = cursor.fetchall()

        return render_template(
            "security_events.html",
            events=events,
            selected_status=status,
            selected_severity=severity,
            search_query=search_query,
            page=page,
            total_pages=total_pages,
            total_events=total_events
        )
    finally:
        connection.close()



@app.route("/events/create", methods=["GET", "POST"])
@role_required("Admin", "Security Analyst")
def create_security_event():
    if request.method == "POST":
        event_type = request.form.get("event_type", "").strip()
        severity = request.form.get("severity", "").strip().upper()
        description = request.form.get("description", "").strip()

        allowed_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

        if not event_type or severity not in allowed_severities:
            return render_template(
                "create_event.html",
                error="Enter an event type and select a valid severity."
            )

        connection = get_db_connection()

        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO security_events
                    (event_type, severity, description, status)
                    VALUES (?, ?, ?, 'OPEN')
                    """,
                    (event_type, severity, description or None)
                )
            connection.commit()

            create_audit_log(
                action="SECURITY_EVENT_CREATED",
                ip_address=request.remote_addr or "127.0.0.1",
                details=f"Created security event: {event_type}; severity: {severity}"
            )

            return redirect(url_for("security_events"))

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    return render_template("create_event.html", error=None)


@app.route("/events/<int:event_id>")
@role_required("Admin", "Security Analyst", "Viewer")
def event_details(event_id):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM security_events WHERE event_id = ?",
                (event_id,)
            )
            event = cursor.fetchone()

        if not event:
            return "Security event not found", 404

        return render_template("event_details.html", event=event)

    finally:
        connection.close()


@app.route("/events/<int:event_id>/resolve", methods=["POST"])
@role_required("Admin", "Security Analyst")
def resolve_security_event(event_id):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE security_events
                SET status = 'RESOLVED'
                WHERE event_id = ? AND status = 'OPEN'
                """,
                (event_id,)
            )
            updated = cursor.rowcount

        connection.commit()

        if updated:
            create_audit_log(
                action="SECURITY_EVENT_RESOLVED",
                ip_address=request.remote_addr or "127.0.0.1",
                details=f"Security event {event_id} marked as resolved"
            )

        return redirect(url_for("security_events"))

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


@app.route("/users", methods=["GET", "POST"])
@role_required("Admin")
def manage_users():
    if request.method == "POST":
        action = request.form.get("action")
        user_id = request.form.get("user_id", type=int)

        if not user_id:
            flash("Invalid user ID.")
            return redirect(url_for("manage_users"))

        # Prevent accidental changes to the currently logged-in Admin.
        if user_id == session.get("user_id"):
            flash("You cannot change your own role or account status here.")
            return redirect(url_for("manage_users"))


        if action == "change_role":
            role_id = request.form.get("role_id", type=int)

            if role_id is None:
                flash("Please select a valid role.")
            else:
                success, message = update_user_role(user_id, role_id)
                flash(message)

                if success:
                    create_audit_log(
                        action="USER_ROLE_CHANGED",
                        ip_address=request.remote_addr or "127.0.0.1",
                        details=(
                            f"Admin {session.get('username')} changed "
                            f"user ID {user_id} to role ID {role_id}"
                        )
                    )

        elif action == "toggle_status":
            is_active = request.form.get("is_active")

            if is_active not in ("0", "1"):
                flash("Invalid account status.")
            else:
                success, message = update_user_status(
                    user_id, int(is_active)
                )
                flash(message)

                if success:
                    status_text = (
                        "activated" if is_active == "1"
                        else "deactivated"
                    )

                    create_audit_log(
                        action="USER_STATUS_CHANGED",
                        ip_address=request.remote_addr or "127.0.0.1",
                        details=(
                            f"Admin {session.get('username')} "
                            f"{status_text} user ID {user_id}"
                        )
                    )


        else:
            flash("Invalid action.")

        return redirect(url_for("manage_users"))

    users = get_all_users()
    roles = get_all_roles()

    return render_template(
        "users.html",
        users=users,
        roles=roles
    )



@app.route("/api/monitor", methods=["GET"])
def monitor_api():
    ip_address = request.remote_addr or "unknown"

    # Record the request in the audit log
    create_audit_log(
        "API_REQUEST",
        ip_address,
        "Request received at /api/monitor"
    )

    # Check whether the request threshold has been reached
    detect_excessive_api_requests(ip_address)

    return {
        "status": "success",
        "message": "API request recorded."
    }, 200




if __name__ == "__main__":
    app.run(debug=True)
