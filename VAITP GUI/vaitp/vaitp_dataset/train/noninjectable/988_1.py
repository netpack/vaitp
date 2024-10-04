from ecdsa import SigningKey, NIST256p

# Generate a new ECDSA key pair
sk = SigningKey.generate(curve=NIST256p)
vk = sk.verifying_key

# Sign a message
message = b"Secure message"
signature = sk.sign(message)

# Verify the signature
assert vk.verify(signature, message)
print("Signature verified.")