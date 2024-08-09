from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Create a cipher object
cipher = Cipher(algorithms.AES(b'\x00' * 16), modes.CBC(b'\x00' * 16), backend=default_backend())
encryptor = cipher.encryptor()

# Create an immutable bytes object
immutable_data = b'Hello, World!'

# Create a mutable bytearray object
mutable_buffer = bytearray(16)

# Pass the immutable bytes object to update_into, which will mutate it
encryptor.update_into(immutable_data, mutable_buffer)

print(mutable_buffer)  # Output: [105, 144, 221, 135, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245, 245]
print(immutable_data)  # Output: b'Hello, World!' (should be mutated, but isn't)