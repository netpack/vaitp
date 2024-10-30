from ecdsa import SigningKey, BadSignatureError

# Generate a signing key
sk = SigningKey.generate()
vk = sk.get_verifying_key()

# Create a message and sign it
message = b"Important message"
signature = sk.sign(message)

# Vulnerable verification (before the patch)
try:
    # This might incorrectly accept a malformed signature
    if vk.verify(signature, message):
        print("Signature is valid!")  # This could be misleading
    else:
        print("Signature is invalid!")
except BadSignatureError:
    print("Caught a bad signature error!")