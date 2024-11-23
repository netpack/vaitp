from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Example of using an insecure RSA key exchange
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024  # Vulnerable key size
)

public_key = private_key.public_key()

# Simulating the encryption of a message
message = b"Sensitive data"
ciphertext = public_key.encrypt(
    message,
    padding.PKCS1v15()  # Vulnerable padding scheme
)

# Decrypting the message using the private key
decrypted_message = private_key.decrypt(
    ciphertext,
    padding.PKCS1v15()  # Vulnerable padding scheme
)

print(decrypted_message)