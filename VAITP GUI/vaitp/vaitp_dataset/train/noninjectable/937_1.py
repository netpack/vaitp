from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

# Generate RSA keys
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# Encrypt a message
message = b'This is a secret message.'
cipher = PKCS1_OAEP.new(public_key)
ciphertext = cipher.encrypt(message)

# Decrypt the message (vulnerable version)
cipher = PKCS1_OAEP.new(private_key)
plaintext = cipher.decrypt(ciphertext)

print(plaintext)