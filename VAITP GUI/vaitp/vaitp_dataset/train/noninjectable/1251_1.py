import subprocess
import tempfile
import os

def encrypt_with_pyrage(recipient, plaintext):
    """Encrypts plaintext using pyrage with a given recipient."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf_plaintext:
        tf_plaintext.write(plaintext)
        plaintext_path = tf_plaintext.name

    with tempfile.NamedTemporaryFile(delete=False) as tf_ciphertext:
        ciphertext_path = tf_ciphertext.name

    try:
        subprocess.run(
            ["pyrage", "-r", recipient, "-o", ciphertext_path, plaintext_path],
            check=True,
            capture_output=True,
        )
        with open(ciphertext_path, "rb") as f:
            ciphertext = f.read()
        return ciphertext
    finally:
        os.remove(plaintext_path)
        os.remove(ciphertext_path)



def decrypt_with_pyrage(identity, ciphertext):
    """Decrypts ciphertext using pyrage with a given identity."""
    with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tf_ciphertext:
        tf_ciphertext.write(ciphertext)
        ciphertext_path = tf_ciphertext.name

    with tempfile.NamedTemporaryFile(delete=False) as tf_plaintext:
        plaintext_path = tf_plaintext.name

    try:
        subprocess.run(
            ["pyrage", "-i", identity, "-o", plaintext_path, ciphertext_path],
            check=True,
            capture_output=True,
        )
        with open(plaintext_path, "r") as f:
            plaintext = f.read()
        return plaintext
    finally:
         os.remove(ciphertext_path)
         os.remove(plaintext_path)

if __name__ == '__main__':
    # Example usage (assuming you have a keypair)
    recipient_key = "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" # Replace with valid recipient public key
    identity_key  = "AGE-SECRET-KEY-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # Replace with valid private key
    plaintext_to_encrypt = "This is a secret message."
    
    ciphertext = encrypt_with_pyrage(recipient_key, plaintext_to_encrypt)
    print(f"Ciphertext: {ciphertext.decode('latin-1')}")

    decrypted_plaintext = decrypt_with_pyrage(identity_key, ciphertext)
    print(f"Decrypted plaintext: {decrypted_plaintext}")