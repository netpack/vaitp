import hashlib
import time

def hash_password(password):
    # Limit the maximum length of the password to prevent DoS
    max_length = 128  # Example limit
    if len(password) > max_length:
        raise ValueError("Password too long")

    # Use a secure hashing algorithm with a fixed iteration count
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 100000)
    return hashed_password

# Example usage
try:
    password = input("Enter your password: ")
    hashed = hash_password(password)
    print("Password hashed successfully.")
except ValueError as e:
    print(e)