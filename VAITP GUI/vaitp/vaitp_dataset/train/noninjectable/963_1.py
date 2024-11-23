import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def get_key(secret: str) -> bytes:
    # Vulnerable key generation: using a simple hash that can lead to insufficient entropy
    return hashlib.md5(secret.encode()).digest()  # MD5 is weak and leads to poor key diversity

def encrypt(plaintext: str, secret: str) -> bytes:
    key = get_key(secret)
    cipher = AES.new(key, AES.MODE_CBC, iv=b'0' * AES.block_size)  # Fixed IV (not secure)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ciphertext

# Example usage
secret_key = "my_secret"
message = "This is a secret message."
encrypted_message = encrypt(message, secret_key)
print(encrypted_message.hex())