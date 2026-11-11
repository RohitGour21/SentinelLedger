# SentinelLedger
### Secure Audit and Threat Monitoring Platform

SentinelLedger is a Flask-based security monitoring application that records system activities, detects suspicious behaviour, and maintains tamper-evident audit logs. It provides a centralized dashboard where authorized users can monitor security events, investigate activities, and verify audit log integrity.

---

## 🔐 Live Demo Access

| Detail | Demo Credentials |
|---|---|
| **Application URL** | `https://sentinelledger.onrender.com` |
| **Username** | `viewer1` |
| **Password** | `ViewerPassword123` |
| **Role** | Viewer |

**How to access:** Open the application URL, enter the demo username and password, and sign in to explore the dashboard, audit logs, analytics, and security events.


---

## Overview

SentinelLedger provides a centralized way to record, monitor, and investigate security-related activities. It combines audit logging, hash-based integrity verification, configurable threat detection, and role-based access control in one web application.

### Core Features

| Feature | Description |
|---|---|
| **Audit Logging** | Records security-related activities with timestamps, IP addresses, actions, and details. |
| **SHA-256 Hash Chaining** | Links audit records cryptographically to make unauthorized modifications detectable. |
| **Audit Verification** | Checks the integrity of audit records and identifies modified entries or broken hash links. |
| **Security Dashboard** | Displays audit statistics, security events, event status, and severity breakdowns. |
| **Threat Detection** | Identifies repeated failed logins, unauthorized access attempts, and excessive API requests. |
| **Security Event Management** | Creates, reviews, and resolves security events with different severity levels. |
| **Audit Log Search** | Supports searching, date filtering, pagination, and CSV export. |
| **Role-Based Access Control** | Provides separate permissions for Admin, Security Analyst, and Viewer. |
| **User Management** | Allows administrators to manage accounts, roles, and account activation. |
| **API Integration** | Accepts security-related events from other applications through an API endpoint. |

---

## How SentinelLedger Works

The application follows a centralized security monitoring workflow:

1. **Activity Collection:** User actions and incoming application events are recorded.
2. **Audit Logging:** Activities are stored in the SQLite database with relevant details and timestamps.
3. **Integrity Protection:** Each audit record is connected to the previous record using SHA-256 hashing.
4. **Threat Detection:** Configurable rules examine activity patterns and identify suspicious behaviour.
5. **Security Event Generation:** When a rule is triggered, a security event is created with an appropriate severity.
6. **Dashboard Monitoring:** Authorized users can view logs, investigate events, and monitor overall security activity.
7. **Integrity Verification:** The audit verification feature checks whether stored records have been modified.

### System Workflow

```text
User Activity / API Events
           |
           v
    Activity Collection
           |
           v
      Audit Logging
           |
           v
    SHA-256 Hash Chain
           |
           v
    Threat Detection
           |
           v
   Security Event Generation
           |
           v
    Centralized Dashboard
           |
           v
   Investigation & Verification
```

---

## User Roles and Permissions

SentinelLedger implements Role-Based Access Control (RBAC) to restrict access according to user responsibilities.

| Functionality | Viewer | Security Analyst | Admin |
|---|:---:|:---:|:---:|
| View dashboard | ✓ | ✓ | ✓ |
| View and search audit logs | ✓ | ✓ | ✓ |
| Export audit logs | ✓ | ✓ | ✓ |
| View security events | ✓ | ✓ | ✓ |
| Verify audit chain | — | ✓ | ✓ |
| Create and resolve security events | — | ✓ | ✓ |
| Manage users and roles | — | — | ✓ |

Unauthorized actions are denied and recorded in the audit log.

---

## Audit Log Integrity – SHA-256 Hash Chaining

One of SentinelLedger's main security features is its tamper-evident audit logging mechanism.

Every audit record contains:
- Action performed
- IP address
- Event details
- Creation timestamp
- Previous record hash
- Current record hash

The current hash is calculated using SHA-256 over the record's data, including its previous hash. The data is serialized as sorted-key JSON before hashing to maintain consistent hash generation.

**How it protects the records:**

- The first record starts with a previous hash of 64 zeros.
- Every subsequent record stores the hash of the previous record.
- Modifying an existing record changes its calculated hash.
- The verification process detects hash mismatches and broken links in the chain.

This makes unauthorized modification detectable. It does not prevent someone with sufficient database access from deleting or replacing the entire database or rewriting the chain.

---

## Threat Detection

SentinelLedger uses configurable security rules to identify suspicious activity.

| Detection Rule | Default Threshold | Time Window |
|---|---:|---:|
| Repeated Failed Logins | 5 attempts | 5 minutes |
| Unauthorized Access | 3 attempts | 5 minutes |
| Excessive API Requests | 100 requests | 1 minute |

Detected activities can generate security events with the following severity levels:

- LOW
- MEDIUM
- HIGH
- CRITICAL

Security events can be reviewed and resolved by authorized users. The system also supports manually creating security events.

---

## External Application Integration

SentinelLedger can receive security-related events from other applications through its API monitoring endpoint:

`POST /api/monitor`

An integrated application can send event information to SentinelLedger, allowing its activities to be recorded and monitored through the central dashboard.

Integration requires the SentinelLedger application URL, the accepted request format, and the API authentication key if authentication is enabled.

External integration is optional. SentinelLedger operates independently without requiring another application.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Application programming |
| Flask | Backend web framework |
| SQLite | Database |
| SQLAlchemy / SQLite database layer | Database operations |
| Flask-WTF | CSRF protection |
| Werkzeug | Password hashing |
| Jinja2 | HTML templating |
| HTML, CSS, JavaScript | Frontend |
| SHA-256 | Audit integrity verification |
| Gunicorn | Production application server |
| GitHub | Version control |
| Render | Cloud deployment |

---

## Project Structure

```text
SentinelLedger/
├── app.py                      # Flask app: routes, role checks, dashboard logic
├── wsgi.py                     # Production entry point (gunicorn wsgi:app)
├── requirements.txt            # Python dependencies
├── render.yaml                 # Render deployment blueprint
├── .env.example                # Template for environment variables
├── .gitignore                  # Excludes .env, venv, databases, caches
├── README.md
│
├── app/
│   ├── __init__.py
│   ├── db.py                   # SQLite connection, schema set-up, start-up admin/users
│   └── services/
│       ├── __init__.py
│       ├── audit_service.py    # Creates hash-chained audit log entries
│       ├── hash_service.py     # Verifies the audit chain
│       ├── auth_service.py     # Registration and authentication
│       ├── user_service.py     # Role and account-status management
│       ├── threat_detector.py  # Repeated failed-login rule
│       └── api_monitor.py      # Excessive API request rule
│
├── database/
│   ├── schema.sql              # SQLite schema and default roles/rules
│   └── schema_mysql.sql        # Original MySQL schema (reference only)
│
├── templates/
│   ├── login.html
│   ├── index.html              # Dashboard
│   ├── audit_logs.html
│   ├── security_events.html
│   ├── event_details.html
│   ├── create_event.html
│   ├── users.html
│   └── verify.html
│
├── create_admin.py             # Create the first Admin (local use)
├── create_viewer.py            # Create a sample Viewer account
├── debug_hash.py               # Recalculate and compare one entry's hash
│
└── test_sqlite_e2e.py          # Full test suite (uses a temporary database)
    test_audit.py, test_verify.py, test_threat_detector.py,
    test_auto_detection.py, test_api_monitor.py, test_db.py, test_app_db.py
                                # Small helper/test scripts
```

*This is an overview of the main project components. Refer to the repository for the complete file structure.*

---

## Running Locally

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd SentinelLedger
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
copy .env.example .env
```

Set the required values in the `.env` file, including a strong Flask secret key.

### 5. Create the first Admin account

```bash
python create_admin.py
```

### 6. Run the application

```bash
python app.py
```

Open:

`http://127.0.0.1:5000`

The SQLite database and required tables are initialized automatically when the application starts.

---

## Environment Variables

| Variable | Purpose |
|---|---|
| `FLASK_SECRET_KEY` | Signs Flask sessions and CSRF tokens. |
| `SESSION_COOKIE_SECURE` | Enables secure cookies when using HTTPS. |
| `DATABASE_PATH` | Optional SQLite database file location. |
| `INITIAL_ADMIN_USERNAME` | Initial administrator username, if startup account creation is configured. |
| `INITIAL_ADMIN_EMAIL` | Initial administrator email. |
| `INITIAL_ADMIN_PASSWORD` | Initial administrator password. |
| `INITIAL_USERS` | Optional additional predefined users, if supported by the application. |
| `SENTINEL_API_KEY` | API authentication key, if required by the integration endpoint. |

Never commit real passwords, secret keys, or `.env` files to GitHub.

---

## Deployment on Render

SentinelLedger can be deployed as a Python Web Service on Render.

**Build Command**

```bash
pip install -r requirements.txt
```

**Start Command**

```bash
gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120
```

Configure the required environment variables in Render and deploy the connected GitHub repository.

### Deployment Notes

- The Free Web Service can spin down after a period of inactivity.
- Its filesystem is temporary, so SQLite data may be lost after restarts, redeployments, or spin-down.
- A single Gunicorn worker is recommended for this SQLite configuration.
- Persistent storage or an external database is required if permanent data retention is needed.

---

## Security Measures

- SHA-256-based audit hash chaining.
- Werkzeug password hashing.
- Role-based access control.
- CSRF protection using Flask-WTF.
- HTTP-only and SameSite session cookies.
- Secure session cookies over HTTPS.
- 30-minute session lifetime.
- API authentication when configured.

---


## Project Objective

The objective of SentinelLedger is to provide a centralized audit and threat monitoring platform that helps organizations record security activities, identify suspicious behaviour, investigate security incidents, and verify the integrity of stored audit records.

**SentinelLedger — Secure Logging. Transparent Monitoring. Trusted Records.**
