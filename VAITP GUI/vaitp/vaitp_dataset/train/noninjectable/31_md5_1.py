import hashlib

# Vulnerable script using MD5
user_input = input("Enter a string to hash using MD5: ")

# Create an MD5 hash object
md5_hash = hashlib.md5()

# Update the hash object with the user's input
md5_hash.update(user_input.encode('utf-8'))

# Get the hexadecimal representation of the MD5 hash
hashed_result = md5_hash.hexdigest()

print("MD5 Hash:", hashed_result)
