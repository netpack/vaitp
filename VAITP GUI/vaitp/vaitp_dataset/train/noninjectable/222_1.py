import ecdsa

def verify(signature, message, public_key):
    vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    try:
        vk.verify(signature, message)
        return True
    except ecdsa.BadSignatureError:
        return False

# Example usage:
public_key = b'\x04\x97\x93\x61\x34\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90'
message = b'Hello, World!'
signature = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # forged signature

if verify(signature, message, public_key):
    print("Signature is valid")
else:
    print("Signature is invalid")