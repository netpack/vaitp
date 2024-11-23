import zlib

def vulnerable_file_compress(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()  # No size limit, potential for buffer overflow
        compressed_data = zlib.compress(data)
    return compressed_data

# Example usage
compressed = vulnerable_file_compress('path/to/input/file')