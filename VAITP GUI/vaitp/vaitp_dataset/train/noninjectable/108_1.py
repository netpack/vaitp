# Import the zlib module
import zlib

# Define some data with many distant matches
data = b'A' * 1000000 + b'B' * 1000000 + b'C' * 1000000

# Compress the data using the zlib module
compressed = zlib.compress(data)

# Decompress the data using the zlib module
decompressed = zlib.decompress(compressed)