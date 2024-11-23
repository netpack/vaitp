from Cryptodome.Cipher import AES

class InsecureEncryption:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv  # Reused IV

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        # Pad data to be multiple of block size
        padded_data = self._pad(data)
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data

    def _pad(self, data):
        # Pad data to be a multiple of the block size
        pad_len = AES.block_size - len(data) % AES.block_size
        return data + bytes([pad_len] * pad_len)

# Example usage
key = b'Sixteen byte key'  # AES-128
iv = b'Sixteen byte iv.'  # Reused IV
insecure_encryption = InsecureEncryption(key, iv)
encrypted = insecure_encryption.encrypt(b'Secret Message')