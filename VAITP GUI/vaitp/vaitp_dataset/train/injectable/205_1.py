import zlib

def decompress(data):
    try:
        # Use zlib.decompress() instead of zlib.decompressobj()
        return zlib.decompress(data)
    except zlib.error as e:
        print(f"Error: {e}")

# Create a valid input with a zlib-compressed string
valid_input = b'\x78\xda\xbc\x02\x00\x00\x00\x00'  # zlib header with a valid window size

try:
    decompressed_data = decompress(valid_input)
    print(f"Decompressed data: {decompressed_data}")
except Exception as e:
    print(f"Error: {e}")