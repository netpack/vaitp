import rsa

# Generate RSA keys
(public_key, private_key) = rsa.newkeys(512)

# Original message
message = b"Secret Message"
# Encrypt the message
ciphertext = rsa.encrypt(message, public_key)

# Introduce a leading null byte
malicious_ciphertext = b"\0" + ciphertext

# Decrypt the ciphertext (vulnerable behavior)
try:
    decrypted_message = rsa.decrypt(malicious_ciphertext, private_key)
    print("Decrypted message:", decrypted_message)
except rsa.DecryptionError:
    print("Decryption failed.")