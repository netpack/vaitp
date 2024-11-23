# Example of how the vulnerability CVE-2024-23342 could be addressed in the ecdsa package

from ecdsa import SigningKey, VerifyingKey, NIST256p

# Securely generate a signing key
def generate_signing_key():
    return SigningKey.generate(curve=NIST256p)

# Sign a message securely
def sign_message(signing_key, message):
    return signing_key.sign(message)

# Verify a signature securely
def verify_signature(verifying_key, message, signature):
    return verifying_key.verify(signature, message)

# Example usage
if __name__ == "__main__":
    message = b"Secure message"
    
    # Generate keys
    signing_key = generate_signing_key()
    verifying_key = signing_key.get_verifying_key()
    
    # Sign the message
    signature = sign_message(signing_key, message)
    
    # Verify the signature
    is_valid = verify_signature(verifying_key, message, signature)
    print("Signature valid:", is_valid)