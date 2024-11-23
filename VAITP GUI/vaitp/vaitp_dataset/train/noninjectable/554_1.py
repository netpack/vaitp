from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def vulnerable_rsa_decrypt(private_key, ciphertext):
    try:
        # Directly decrypting without constant-time checks can lead to timing attacks
        plaintext = private_key.decrypt(
            ciphertext,
            padding.PKCS1v15()
        )
        return plaintext
    except Exception as e:
        # Different exceptions may lead to timing discrepancies
        return None

# Example usage
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Simulated ciphertext (should be a valid PKCS#1 v1.5 ciphertext)
ciphertext = b'...'  # Replace with actual ciphertext

plaintext = vulnerable_rsa_decrypt(private_key, ciphertext)