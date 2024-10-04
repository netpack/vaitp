# Import the lzma module
import lzma

# Define a string to compress
string = "Hello, world!"

# Compress the string using lzma.compress
compressed = lzma.compress(string.encode())

# Print the compressed string
print(compressed)

# Decompress the string using lzma.decompress
decompressed = lzma.decompress(compressed).decode()

# Print the decompressed string
print(decompressed)