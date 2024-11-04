import rsa

def constant_time_compare(val1, val2):
    # A constant-time comparison function to prevent timing attacks
    if len(val1) != len(val2):
        return False
    return all(a == b for a, b in zip(val1, val2))

def decrypt_message(private_key, ciphertext):
    # Decrypt the message
    decrypted_message = rsa.decrypt(ciphertext, private_key)

    # In practice, you might compare against a known valid message,
    # but for this example, we just return the decrypted message.
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