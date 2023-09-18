from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Create a mutable bytearray as the output buffer
outbuf = bytearray(32)

# Create an AES cipher in ECB mode
cipher = Cipher(algorithms.AES(b"\x00" * 32), modes.ECB())

# Encrypt data into the mutable output buffer
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(b"\x00" * 16) + encryptor.finalize()

# Copy the encrypted data to the output buffer
outbuf[:len(encrypted_data)] = encrypted_data

# Print the contents of the output buffer
print(outbuf)
