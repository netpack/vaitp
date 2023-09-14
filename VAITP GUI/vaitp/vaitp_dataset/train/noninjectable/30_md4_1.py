import hashlib

# Input data to be hashed
input_data = input("Enter data do hash using MD4: ")

# Create an MD4 hash object
md4_hash = hashlib.new("md4")

# Update the hash object with the input data
md4_hash.update(input_data.encode('utf-8'))

# Get the hexadecimal representation of the MD4 hash
md4_hexdigest = md4_hash.hexdigest()

print(f"Input data: {input_data}")
print(f"MD4 Hash: {md4_hexdigest}")
