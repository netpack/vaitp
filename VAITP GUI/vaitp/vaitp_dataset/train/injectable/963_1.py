import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib

def generate_secure_key(secret: str) -> bytes:
    # Use a secure hash function to generate a key from the secret
    return hashlib.sha256(secret.encode()).digest()

def encrypt(plaintext: str, secret: str) -> bytes:
    key = generate_secure_key(secret)
    iv = os.urandom(AES.block_size)  # Generate a random IV for each encryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext  # Prepend IV for use in decryption

# Example usage
secret_key = "my_secure_secret"
message = "This is a secret message."
encrypted_message = encrypt(message, secret_key)
print(encrypted_message.hex())