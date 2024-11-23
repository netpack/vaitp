# hashing.py

import hashlib

def insecure_hash(data):
    # Using MD5 hashing algorithm (insecure)
    return hashlib.md5(data.encode()).hexdigest()

# Example usage
if __name__ == "__main__":
    data_to_hash = "example_data"
    print("Insecure hash:", insecure_hash(data_to_hash))