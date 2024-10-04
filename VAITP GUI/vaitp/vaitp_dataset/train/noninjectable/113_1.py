from Crypto.Cipher import AES
# The following line creates an AES cipher object with a 16-byte key
cipher = AES.new(b'\x00' * 16)
# The following line encrypts a message shorter than 16 bytes
# This will cause an integer overflow and a segmentation fault
ciphertext = cipher.encrypt(b'Hello')