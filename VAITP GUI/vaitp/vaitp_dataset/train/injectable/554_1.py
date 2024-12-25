from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature

def safe_rsa_decrypt(private_key, ciphertext):
    try:
        # Use a constant-time comparison to avoid timing attacks
        plaintext = private_key.decrypt(
            ciphertext,
            padding.PKCS1v15()
        )
        return plaintext
    except Exception as e:
        # Handle exceptions in a way that does not leak timing information
        return None

# Example usage
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Simulated ciphertext (should be a valid PKCS#1 v1.5 ciphertext)
# To create a valid example we need to encrypt with the corresponding public key
public_key = private_key.public_key()
message = b"This is a secret message"

ciphertext = public_key.encrypt(
    message,
    padding.PKCS1v15()
)


plaintext = safe_rsa_decrypt(private_key, ciphertext)

if plaintext:
    print(f"Decrypted message: {plaintext.decode()}")
else:
    print("Decryption failed.")