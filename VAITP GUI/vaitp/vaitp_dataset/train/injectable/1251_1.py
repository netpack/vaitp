import io
import secrets

from pyrage import x25519, encrypt, decrypt

def generate_key_pair():
  """Generates a new X25519 key pair."""
  sk = x25519.PrivateKey.generate()
  pk = sk.public_key()
  return sk, pk

def encrypt_data(data: bytes, recipient_public_key: x25519.PublicKey) -> bytes:
    """Encrypts data using the given recipient public key."""
    return encrypt(data, [recipient_public_key])

def decrypt_data(encrypted_data: bytes, recipient_private_key: x25519.PrivateKey) -> bytes:
    """Decrypts data using the given recipient private key."""
    return decrypt(encrypted_data, recipient_private_key)


def fixed_encryption_example():
    """Demonstrates secure encryption and decryption using pyrage."""

    # Generate a key pair for the recipient
    recipient_private_key, recipient_public_key = generate_key_pair()


    # Data to be encrypted
    original_data = b"This is some very sensitive data."

    # Encrypt the data
    encrypted_data = encrypt_data(original_data, recipient_public_key)

    # Decrypt the data
    decrypted_data = decrypt_data(encrypted_data, recipient_private_key)


    assert decrypted_data == original_data
    print("Encryption and decryption successful. Data integrity is verified.")


if __name__ == "__main__":
    fixed_encryption_example()