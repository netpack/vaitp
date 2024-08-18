import hashlib

#This is a non-vulnerable example that does not require the ctypes C Lib, so not vulnerable..
def hash_data(data):
    # Use the built-in hashlib library to hash the data
    hash_object = hashlib.sha3_256()
    hash_object.update(data)
    return hash_object.digest()

# Example usage:
data = b"Hello, World!"
hashed_data = hash_data(data)
print(hashed_data.hex())
