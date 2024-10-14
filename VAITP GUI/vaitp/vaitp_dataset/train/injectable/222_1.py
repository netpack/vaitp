import ecdsa

def verify(signature, message, public_key):
    vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    if not signature:  # Check for zero-filled signature
        return False
    try:
        vk.verify(signature, message)
        return True
    except ecdsa.BadSignatureError:
        return False

# Example usage:
public_key = b'\x04\x97\x93\x61\x34\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90'
message = b'Hello, World!'
signature = b'\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef'  # valid signature

if verify(signature, message, public_key):
    print("Signature is valid")
else:
    print("Signature is invalid")