```
```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os

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

public_key = private_key.public_key()

# Simulate encryption to create a valid ciphertext
plaintext_original = b"This is a secret message"
ciphertext = public_key.encrypt(
    plaintext_original,
    padding.PKCS1v15()
)



plaintext = vulnerable_rsa_decrypt(private_key, ciphertext)

if plaintext:
  print(f"Decrypted plaintext: {plaintext.decode()}")
else:
  print("Decryption failed.")