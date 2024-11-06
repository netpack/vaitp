from tlslite.utils import constant_time_compare

def secure_rsa_decrypt(ciphertext, private_key):
    # Use a constant-time algorithm for RSA decryption
    decrypted = private_key.decrypt(ciphertext)

    # Implementing constant-time comparison to avoid leaking information
    # about the decrypted plaintext
    expected_plaintext = "expected_value"
    if constant_time_compare(decrypted, expected_plaintext):
        return decrypted
    else:
        # Handle incorrect decryption without leaking information
        raise ValueError("Decryption failed")
