# hashing.py

import hashlib

# Remove the MD5 hashing function to fix the vulnerability

def secure_hash(data):
    # Use a more secure hashing algorithm, such as SHA-256
    return hashlib.sha256(data.encode()).hexdigest()

# Example usage
if __name__ == "__main__":
    data_to_hash = "example_data"
    print("Secure hash:", secure_hash(data_to_hash))