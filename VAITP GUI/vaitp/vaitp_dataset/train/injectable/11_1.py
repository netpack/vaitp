import hmac
import secrets

def verify_signature(message, signature, key):
    expected_signature = hmac.new(key, message, 'sha256').digest()
    if secrets.compare_digest(expected_signature, signature):
        return True
    else:
        return False

# Example usage:
key = b"my_secret_key"
message = b"Hello, World!"
signature = hmac.new(key, message, 'sha256').digest()

# This will take a constant time to compare, making it safe from timing attacks
if verify_signature(message, signature, key):
    print("Signature is valid")
else:
    print("Signature is invalid")