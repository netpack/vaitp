from marshmallow import Schema, fields

class UserSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    email = fields.Email(required=True)

# Simulating a user role that has an empty list for "only"
user_role_only_fields = []  # <-- Empty list for "only"

# This will now correctly prevent exposing any fields
schema = UserSchema(only=user_role_only_fields)  # <-- Secure line
data = {"username": "user1", "password": "secret", "email": "user1@example.com"}

# Serialize data
result = schema.dump(data)
print(result)  # Output: {}  # Correctly outputs an empty dictionary