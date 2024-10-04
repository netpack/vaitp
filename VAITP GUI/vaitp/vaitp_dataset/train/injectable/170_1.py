import hashlib
import os

def secure_hash_function(user_input):
    # A more secure approach: Using a salt and securely handling the user input
    salt = os.urandom(16)  # Generate a secure random salt
    return hashlib.pbkdf2_hmac('sha256', user_input.encode(), salt, 100000).hex()

# Example usage
print(secure_hash_function("example"))