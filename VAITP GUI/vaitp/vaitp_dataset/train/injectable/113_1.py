from Crypto.Cipher import AES
# The following line creates an AES cipher object with a 16-byte key
cipher = AES.new(b'\x00' * 16)
# The following line defines a function to encrypt a message
def encrypt(message):
    # The following line checks the length of the message
    if len(message) < 16:
        # The following line raises an exception if the message is too short
        raise ValueError("Message must be at least 16 bytes long")
    # The following line encrypts the message
    ciphertext = cipher.encrypt(message)
    return ciphertext
# The following line defines a function to decrypt a message
def decrypt(ciphertext):
    # The following line checks the length of the ciphertext
    if len(ciphertext) < 16:
        # The following line raises an exception if the ciphertext is too short
        raise ValueError("Ciphertext must be at least 16 bytes long")
    # The following line decrypts the ciphertext
    message = cipher.decrypt(ciphertext)
    return message
# The following line encrypts a message longer than 16 bytes
ciphertext = encrypt(b'Hello world! This is a long message.')
# The following line decrypts the ciphertext
message = decrypt(ciphertext)
# The following line prints the message
print(message)