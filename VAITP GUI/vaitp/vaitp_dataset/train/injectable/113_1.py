from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# The following line creates an AES cipher object with a 16-byte key
key = b'\x00' * 16
cipher = AES.new(key, AES.MODE_ECB)

# The following line defines a function to encrypt a message
def encrypt(message):
    # The following line pads the message to be a multiple of 16 bytes
    padded_message = pad(message, AES.block_size)
    # The following line encrypts the message
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext

# The following line defines a function to decrypt a message
def decrypt(ciphertext):
    # The following line decrypts the ciphertext
    padded_message = cipher.decrypt(ciphertext)
    # The following line unpads the message
    message = unpad(padded_message, AES.block_size)
    return message

# The following line encrypts a message longer than 16 bytes
ciphertext = encrypt(b'Hello world! This is a long message.')
# The following line decrypts the ciphertext
message = decrypt(ciphertext)
# The following line prints the message
print(message)