
from app.services.audit_service import create_audit_log
from app.services.threat_detector import detect_repeated_failed_logins

test_ip = "192.0.2.101"

# Generate five simulated failed-login audit records.
for i in range(5):
    create_audit_log(
        action="LOGIN_FAILED",
        ip_address=test_ip,
        details=f"Simulated failed login attempt {i + 1}"
    )

    print(f"Recorded failed login attempt {i + 1}")

# Check whether the detector creates a security event.
alert_created = detect_repeated_failed_logins(test_ip)

if alert_created:
    print("SUCCESS: High-severity security event created.")
else:
    print("No new alert created. Check existing alerts if applicable.")
