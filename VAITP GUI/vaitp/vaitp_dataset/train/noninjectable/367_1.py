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

# Decoding the token without proper validation (vulnerable code)
decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'], options={"verify_signature": False})

print("Decoded Payload:", decoded_payload)