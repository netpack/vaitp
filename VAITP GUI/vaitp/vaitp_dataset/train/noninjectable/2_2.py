from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Create an immutable output buffer
outbuf = b"\x00" * 32

# Create an AES cipher in ECB mode
cipher = Cipher(algorithms.AES(b"\x00" * 32), modes.ECB())

# Encrypt data into the immutable output buffer
encryptor = cipher.encryptor()
encryptor.update_into(b"\x00" * 16, outbuf)

# Print the contents of the output buffer
print(outbuf)