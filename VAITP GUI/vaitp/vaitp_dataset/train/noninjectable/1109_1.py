from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate a private key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
# Create a certificate with a mismatched public key
mismatched_public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()).public_key()

# Attempt to serialize with mismatched keys and an encryption algorithm
from cryptography.hazmat.primitives.serialization import pkcs12

# This call would crash the Python process in versions prior to 42.0.4
pkcs12.serialize_key_and_certificates(
    name=b"test",
    key=private_key,
    cert=mismatched_public_key,
    encryption_algorithm=pkcs12.encryption_builder().hmac_hash(b"password"),
)