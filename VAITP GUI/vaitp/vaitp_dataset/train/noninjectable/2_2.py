from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Create an immutable output buffer
outbuf = bytearray(b"\x00" * 32)

# Create an AES cipher in ECB mode
cipher = Cipher(algorithms.AES(b"\x00" * 32), modes.ECB())

# Encrypt data into the output buffer
encryptor = cipher.encryptor()
padder = padding.PKCS7(algorithms.AES.block_size).padder()
padded_data = padder.update(b"\x00" * 16) + padder.finalize()
encryptor.update_into(padded_data, outbuf)


# Print the contents of the output buffer
print(bytes(outbuf))