import hashlib

# Input data
data = input("Enter the data to hash using SHA-1: ")

# Create an SHA-1 hash object
sha1_hash = hashlib.sha1()

# Update the hash object with the input data
sha1_hash.update(data.encode('utf-8'))

# Get the hexadecimal representation of the hash
hashed_data = sha1_hash.hexdigest()

# Print the SHA-1 hash
print("SHA-1 Hash:", hashed_data)

