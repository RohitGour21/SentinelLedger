
from app.services.hash_service import verify_audit_chain

result = verify_audit_chain()

print("Valid:", result["valid"])
print("Message:", result["message"])

if result["valid"]:
    print("Total logs:", result["total_logs"])
else:
    print("Problem at log ID:", result["log_id"])
