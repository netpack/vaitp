from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate a random 16-byte key
key = os.urandom(16)

# Generate a random 16-byte IV
iv = os.urandom(16)

# Create a cipher object
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Create an immutable bytes object
immutable_data = b'Hello, World!'

# Create a mutable bytearray object
mutable_buffer = bytearray(len(immutable_data))

# Pass the immutable bytes object to update_into, which will mutate the buffer
encryptor.update_into(immutable_data, mutable_buffer)

print(mutable_buffer)
print(immutable_data)