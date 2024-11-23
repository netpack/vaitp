# Fixed code: Avoid importing the vulnerable package
# Instead of using the democritus-hashes package, we will use a secure alternative.

# Secure alternative import
from hashlib import sha256

def secure_hash(data):
    """Generates a secure SHA-256 hash of the input data."""
    return sha256(data.encode()).hexdigest()

# Example usage
if __name__ == "__main__":
    user_input = "sensitive data"
    print("Secure hash:", secure_hash(user_input))