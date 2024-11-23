import hashlib

class VulnerableHash:
    def __init__(self):
        self.hasher = hashlib.sha256()
        self.total_length = 0

    def update(self, data):
        self.hasher.update(data)
        self.total_length += len(data)  # Potential for integer overflow here

    def digest(self):
        return self.hasher.digest()

# Example usage
vulnerable_hash = VulnerableHash()
# Simulating a large amount of data
vulnerable_hash.update(b"A" * (2**31))  # Adding 2GB of data
print(vulnerable_hash.digest())