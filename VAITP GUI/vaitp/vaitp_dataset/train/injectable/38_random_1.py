from cryptography.fernet import Fernet

# Generate a secure cryptographic key
key = Fernet.generate_key()

# Initialize the Fernet cipher with the key
cipher_suite = Fernet(key)

# Simulate using the key for encryption and decryption
plaintext = "This is a secret message.".encode('utf-8')

# Encrypt the message
encrypted_data = cipher_suite.encrypt(plaintext)

print("Original Message:", plaintext.decode('utf-8'))
print("Encrypted Message:", encrypted_data.decode('utf-8'))

# Decrypt the message
decrypted_data = cipher_suite.decrypt(encrypted_data)

print("Decrypted Message:", decrypted_data.decode('utf-8'))
