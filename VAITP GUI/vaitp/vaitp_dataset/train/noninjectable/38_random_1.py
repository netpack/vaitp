import random

# Generate a pseudo-random integer as a cryptographic key (vulnerable)
key = random.randint(1, 1000000)

# Simulate using the key for encryption or security
plaintext = "This is a secret message."
encrypted_data = ""

for char in plaintext:
    # Vulnerable: XOR operation for encryption with a weak key
    encrypted_char = chr(ord(char) ^ key)
    encrypted_data += encrypted_char

print("Original Message:", plaintext)
print("Encrypted Message:", encrypted_data)

# Attempt to decrypt the message with the same weak key
decrypted_data = ""

for char in encrypted_data:
    # Vulnerable: XOR operation for decryption with the same weak key
    decrypted_char = chr(ord(char) ^ key)
    decrypted_data += decrypted_char

print("Decrypted Message:", decrypted_data)

