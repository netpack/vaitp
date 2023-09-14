import hashlib

# Input data to be hashed
data = input("Enter data to hash using MD2: ")

# Create an MD2 hash object
md2_hash = hashlib.new('md2')

# Update the hash object with the input data
md2_hash.update(data.encode('utf-8'))

# Get the hexadecimal representation of the MD2 hash
md2_hex_digest = md2_hash.hexdigest()

# Print the MD2 hash
print("MD2 Hash:", md2_hex_digest)
