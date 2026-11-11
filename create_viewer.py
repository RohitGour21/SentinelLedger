
from app.services.auth_service import register_user

success, message = register_user(
    username="test_viewer",
    email="test_viewer@example.com",
    password="ViewerTest@123",
    role_id=3
)

print(message)
