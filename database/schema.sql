-- SentinelLedger SQLite schema.
-- (The original MySQL schema is preserved in database/schema_mysql.sql.)
-- Every statement is idempotent, so it is safe to run on every start-up.

CREATE TABLE IF NOT EXISTS roles (
    role_id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role_id INT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(role_id)
);

CREATE TABLE IF NOT EXISTS resources (
    resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_name VARCHAR(150) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_clients (
    client_id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_name VARCHAR(100) NOT NULL,
    api_key_hash VARCHAR(255) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INT NULL,
    resource_id INT NULL,
    client_id INT NULL,
    action VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    details TEXT,
    previous_hash CHAR(64),
    entry_hash CHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (resource_id) REFERENCES resources(resource_id),
    FOREIGN KEY (client_id) REFERENCES api_clients(client_id)
);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs (created_at);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs (user_id);

CREATE TABLE IF NOT EXISTS security_rules (
    rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(255),
    threshold_value INT NOT NULL,
    time_window_minutes INT NOT NULL DEFAULT 5,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    is_enabled BOOLEAN NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS security_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INT NULL,
    log_id INT NULL,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (rule_id) REFERENCES security_rules(rule_id),
    FOREIGN KEY (log_id) REFERENCES audit_logs(log_id)
);
CREATE INDEX IF NOT EXISTS idx_event_status ON security_events (status);
CREATE INDEX IF NOT EXISTS idx_event_detected_at ON security_events (detected_at);

-- Reference data the application code depends on.
-- The original MySQL schema did not include these rows (they were inserted
-- by hand), so a brand-new SQLite database needs them.
-- role_id 1/3 are relied on by create_admin.py and create_viewer.py.
INSERT OR IGNORE INTO roles (role_id, role_name, description) VALUES
    (1, 'Admin', 'Full access, including user management'),
    (2, 'Security Analyst', 'Can review and resolve security events'),
    (3, 'Viewer', 'Read-only access');

-- NOTE: thresholds below are defaults. Adjust them to match the values in
-- your local MySQL "security_rules" table.
INSERT OR IGNORE INTO security_rules
    (rule_name, description, threshold_value, time_window_minutes, severity, is_enabled)
VALUES
    ('Repeated Failed Logins', 'Repeated failed login attempts from one IP', 5, 5, 'HIGH', 1),
    ('Unauthorized Access', 'Repeated unauthorized page access attempts from one IP', 3, 5, 'HIGH', 1),
    ('Excessive API Requests', 'Excessive API requests from one IP', 100, 1, 'HIGH', 1);
