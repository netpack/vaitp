from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def vulnerable_finalize_with_tag(key, iv, ciphertext, tag):
    # No validation of the tag length
    # This could allow an attacker to pass a short tag
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    
    # Attempt to finalize decryption
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext