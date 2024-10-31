import secrets
import string

def generate_nonce(length=8):
    """Generate a nonce using a cryptographically secure random generator."""
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

# Example usage
nonce = generate_nonce()
print("Nonce:", nonce)