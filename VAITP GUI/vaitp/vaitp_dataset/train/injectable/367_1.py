import jwt

# Secret key for signing the JWT
SECRET_KEY = 'my_secret_key'

# Create a JWT token
payload = {
    'user_id': 123,
    'role': 'user'
}

# Sign the token
token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

print("Original Token:", token)

# Decoding the token with proper validation (patched code)
try:
    decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    print("Decoded Payload:", decoded_payload)
except jwt.InvalidTokenError as e:
    print("Invalid token:", e)