import jwt

# Define a secret key
SECRET_KEY = 'your_secret_key'

# Example of a JWT token (for demonstration purposes)
token = 'your_jwt_token_here'

# Fix for CVE-2022-29217: Specify allowed algorithms explicitly
try:
    decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])  # Specify the algorithm
    print(decoded_token)
except jwt.InvalidTokenError as e:
    print(f"Invalid token: {e}")