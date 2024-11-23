import zlib

def safe_file_compress(file_path):
    # Limit the maximum size of the input to prevent buffer overflow
    max_size = 2**20  # 1 MB for example
    with open(file_path, 'rb') as f:
        data = f.read(max_size)
        if len(data) >= max_size:
            raise ValueError("Input file is too large.")
        compressed_data = zlib.compress(data)
    return compressed_data

# Example usage
try:
    compressed = safe_file_compress('path/to/input/file')
except ValueError as e:
    print(e)