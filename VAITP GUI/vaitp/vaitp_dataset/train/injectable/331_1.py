from cryptography.fernet import Fernet

# Generate a key
key = Fernet.generate_key()
cipher = Fernet(key)

# Example of encrypting a large message with size check
large_message = b"A" * (10**6)  # 1 MB of data

# Check for maximum allowed size before encrypting
MAX_SIZE = 2**20  # 1 MB as an example limit
if len(large_message) > MAX_SIZE:
    raise ValueError("Message is too large to encrypt")

ciphertext = cipher.encrypt(large_message)