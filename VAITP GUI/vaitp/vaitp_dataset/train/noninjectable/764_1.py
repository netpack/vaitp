import hashlib

def hash_password(password):
    # No length check for the password, allowing very long passwords
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

# Example usage
password = input("Enter your password: ")
hashed = hash_password(password)
print("Password hashed successfully.")