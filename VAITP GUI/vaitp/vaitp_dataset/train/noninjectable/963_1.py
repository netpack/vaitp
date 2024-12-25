import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def get_key(secret: str) -> bytes:
    # Improved key generation using SHA256 for better security
    return hashlib.sha256(secret.encode()).digest()

def encrypt(plaintext: str, secret: str) -> bytes:
    key = get_key(secret)
    iv = get_random_bytes(AES.block_size) # Generate a random IV for each encryption
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ciphertext  # Include IV at the beginning of the ciphertext

# Example usage
secret_key = "my_secret"
message = "This is a secret message."
encrypted_message = encrypt(message, secret_key)
print(encrypted_message.hex())