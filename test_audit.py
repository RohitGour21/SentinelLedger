
from app.services.audit_service import create_audit_log

log_id = create_audit_log(
    action="LOGIN_SUCCESS",
    ip_address="127.0.0.1",
    details="Test audit entry"
)

print("Audit log created successfully!")
print("Log ID:", log_id)
