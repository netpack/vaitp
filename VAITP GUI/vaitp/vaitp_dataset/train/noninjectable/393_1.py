import rsa

def decrypt_message(private_key, ciphertext):
    # This is a simplified example; real-world code should handle exceptions and errors.
    decrypted_message = rsa.decrypt(ciphertext, private_key)
    return decrypted_message

# Example usage
private_key, public_key = rsa.newkeys(512)
ciphertext = rsa.encrypt(b"Secret Message", public_key)

# Decrypting the message
try:
    plaintext = decrypt_message(private_key, ciphertext)
    print(plaintext.decode())
except rsa.DecryptionError:
    print("Decryption failed.")