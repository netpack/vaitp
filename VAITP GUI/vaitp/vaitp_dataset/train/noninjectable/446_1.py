def vulnerable_rsa_decrypt(ciphertext, private_key):
    # This is a simplified example of RSA decryption that may leak information
    decrypted = private_key.decrypt(ciphertext)
    # Potentially leaking information about the plaintext
    return decrypted