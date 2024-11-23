from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def secure_aes_encrypt(key, iv, plaintext):
    # Ensure that the key and iv are of the correct length
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be either 16, 24, or 32 bytes long.")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes long.")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ciphertext

def secure_aes_decrypt(key, iv, ciphertext):
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be either 16, 24, or 32 bytes long.")
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes long.")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# Example usage
key = os.urandom(16)  # Securely generate a random key
iv = os.urandom(16)   # Securely generate a random IV
plaintext = "This is a secret message."

ciphertext = secure_aes_encrypt