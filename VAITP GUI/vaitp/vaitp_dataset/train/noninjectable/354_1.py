from ecdsa import VerifyingKey, BadSignatureError

# Assume we have a public key and a malformed signature
public_key = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
malformed_signature = b"malformed_signature_data"

# Create a VerifyingKey object
vk = VerifyingKey.from_pem(public_key)

try:
    # Attempt to verify the malformed signature
    vk.verify(malformed_signature, b"message")
except BadSignatureError:
    print("Signature verification failed.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")