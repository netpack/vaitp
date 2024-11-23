from Crypto.Cipher import AES

def vulnerable_aes_encrypt(key, iv, plaintext):
    # This code does not properly validate the length of the IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)  # Assume plaintext is already padded
    return ciphertext

def vulnerable_aes_decrypt(key, iv, ciphertext):
    # This code does not properly validate the length of the IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)  # Assume ciphertext is valid
    return plaintext

# Example usage
key = b'16_byte_key_123'  # Key should be 16, 24, or 32 bytes long
iv = b'16_byte_iv_12345'  # IV should be 16 bytes long, but this is not validated
plaintext = b'This is a secret message that needs padding.'

ciphertext = vulnerable_aes_encrypt(key, iv, plaintext)