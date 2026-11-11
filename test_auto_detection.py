
from app.services.audit_service import create_audit_log
from app.services.api_monitor import detect_excessive_api_requests

test_ip = "192.0.2.101"

# Generate 100 simulated API requests.
for i in range(100):
    create_audit_log(
        action="API_REQUEST",
        ip_address=test_ip,
        details=f"API detection test - request {i + 1}"
    )

    if (i + 1) % 20 == 0:
        print(f"Recorded {i + 1} API requests")

# Check whether the detector creates a security event.
alert_created = detect_excessive_api_requests(test_ip)

if alert_created:
    print("SUCCESS: Excessive API request alert created.")
else:
    print("No new alert created. Check the threshold and existing alerts.")
