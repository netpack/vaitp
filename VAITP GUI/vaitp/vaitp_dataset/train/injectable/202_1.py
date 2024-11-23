import hashlib

class SafeHash:
    def __init__(self):
        self.hasher = hashlib.sha256()
        self.total_length = 0

    def update(self, data):
        data_length = len(data)
        if self.total_length + data_length > 2**63 - 1:
            raise ValueError("Data length exceeds the maximum allowed limit.")
        self.hasher.update(data)
        self.total_length += data_length

    def digest(self):
        return self.hasher.digest()

# Example usage
safe_hash = SafeHash()
safe_hash.update(b"some data")
print(safe_hash.digest())