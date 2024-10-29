from cryptography.fernet import Fernet

# Generate a key
key = Fernet.generate_key()
cipher = Fernet(key)

# Example of encrypting a large message
large_message = b"A" * (10**9)  # 1 GB of data
ciphertext = cipher.encrypt(large_message)