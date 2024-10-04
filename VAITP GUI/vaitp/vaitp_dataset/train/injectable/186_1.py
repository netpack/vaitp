import hashlib
import os

def generate_secure_hash_with_salt(user_input):
    # Generating a secure, random salt
    salt = os.urandom(16)
    data_to_hash = salt + user_input.encode()
    return hashlib.sha256(data_to_hash).hexdigest(), salt

# Example of generating a secure hash
user_input = "sensitive_data"
hashed_value, used_salt = generate_secure_hash_with_salt(user_input)
print(hashed_value)