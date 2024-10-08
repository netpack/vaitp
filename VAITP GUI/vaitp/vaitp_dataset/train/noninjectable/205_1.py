import zlib

def decompress(data):
    d = zlib.decompressobj()
    return d.decompress(data)

# Create a malicious input with a negative signed integer
malicious_input = b'\x78\xda\xbc\x02\xff\xff\xff\xff'  # zlib header with a negative window size

try:
    decompress(malicious_input)
except Exception as e:
    print(f"Error: {e}")