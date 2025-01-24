import os
import tempfile
from ecdsa import VerifyingKey, SigningKey, NIST256
from ecdsa.util import sigencode_der, sigdecode_der
import hashlib
import base64

def generate_key_pair():
    sk = SigningKey.generate(curve=NIST256)
    vk = sk.verifying_key
    return sk.to_pem(), vk.to_pem()

def sign_message(sk_pem, message):
    sk = SigningKey.from_pem(sk_pem)
    signature = sk.sign(message, hashfunc=hashlib.sha256, sigencode=sigencode_der)
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(vk_pem, message, signature):
    vk = VerifyingKey.from_pem(vk_pem)
    try:
        signature = base64.b64decode(signature)
        vk.verify(signature, message, hashfunc=hashlib.sha256, sigdecode=sigdecode_der)
        return True
    except Exception:
        return False


if __name__ == '__main__':
    sk_pem, vk_pem = generate_key_pair()
    message = b"This is a secret message"
    signature = sign_message(sk_pem, message)

    if verify_signature(vk_pem, message, signature):
        print("Signature verified successfully.")
    else:
        print("Signature verification failed.")

    tampered_message = b"This is a modified message"
    if verify_signature(vk_pem, tampered_message, signature):
        print("Tampered message verification should have failed but passed which means there is a vulnarability")
    else:
        print("Tampered message verification failed, which is correct")

    tampered_signature = base64.b64encode(os.urandom(100)).decode('utf-8')
    if verify_signature(vk_pem, message, tampered_signature):
        print("Tampered signature verification should have failed but passed which means there is a vulnarability")
    else:
       print("Tampered signature verification failed, which is correct")
