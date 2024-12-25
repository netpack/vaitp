from Crypto.Cipher import AES
# The following line creates an AES cipher object with a 16-byte key
key = b'\x00' * 16
cipher = AES.new(key, AES.MODE_ECB) # Added mode of operation
# The following line encrypts a message shorter than 16 bytes
# This will cause an integer overflow and a segmentation fault if no padding
message = b'Hello'
padding_length = 16 - len(message) % 16
message += bytes([padding_length] * padding_length)

ciphertext = cipher.encrypt(message)