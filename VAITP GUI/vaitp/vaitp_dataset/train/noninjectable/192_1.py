import audioop
import sys

# Vulnerable usage of audioop.lin2lin
def vulnerable_lin2lin(data, nchannels, width, new_nchannels, new_width):
    # No checks for input size, which can lead to integer overflow
    return audioop.lin2lin(data, width, new_width, new_nchannels)

# Example usage that could trigger the vulnerability
# Limit data size to avoid MemoryError when creating the bytes object
max_data_size = sys.maxsize // 4 # Integer division to make it smaller
large_data = b'\x00' * min(2**20, max_data_size)  # Simulating a large input that could cause overflow, but also avoid massive memory allocation
try:
    result = vulnerable_lin2lin(large_data, 1, 2, 2, 2)
except Exception as e:
    print(f"An exception occurred: {e}")