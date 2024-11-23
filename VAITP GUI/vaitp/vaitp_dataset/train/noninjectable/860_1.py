import jwt

# Define a secret key
SECRET_KEY = 'your_secret_key'

# Example of a JWT token (for demonstration purposes)
token = 'your_jwt_token_here'

# Vulnerable code: using default algorithms without specifying allowed ones
try:
    decoded_token = jwt.decode(token, SECRET_KEY)  # No explicit algorithm specified
    print(decoded_token)
except jwt.InvalidTokenError as e:
    print(f"Invalid token: {e}")