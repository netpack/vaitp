from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate a private key and a public key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

# Create a certificate that does not match the private key
# (In a real scenario, you'd use a proper certificate)
cert_mismatched = serialization.load_pem_public_key(b"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----", backend=default_backend())

# Attempt to serialize with mismatched keys and an encryption algorithm
try:
    from cryptography.hazmat.primitives.serialization import pkcs12

    # This will raise a ValueError in version 42.0.4 and later
    pkcs12.serialize_key_and_certificates(
        name=b"test",
        key=private_key,
        cert=cert_mismatched,
        encryption_algorithm=pkcs12.encryption_builder().hmac_hash(b"password"),
    )
except ValueError as e:
    print(f"Caught expected ValueError: {e}")