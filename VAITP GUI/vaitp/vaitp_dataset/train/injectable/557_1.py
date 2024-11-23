from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

class SecureEncryption:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        # Generate a unique IV for each encryption
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        # Pad data to be multiple of block size
        padded_data = self._pad(data)
        encrypted_data = iv + cipher.encrypt(padded_data)
        return encrypted_data

    def _pad(self, data):
        # Pad data to be a multiple of the block size
        pad_len = AES.block_size - len(data) % AES.block_size
        return data + bytes([pad_len] * pad_len)

# Example usage
key = get_random_bytes(16)  # AES-128
secure_encryption = SecureEncryption(key)
encrypted = secure_encryption.encrypt(b'Secret Message')