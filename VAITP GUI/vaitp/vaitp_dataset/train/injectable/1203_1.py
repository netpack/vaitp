def safe_strncpy(dest, src, dest_size):
    # Ensure we do not exceed the destination buffer size
    if len(src) >= dest_size:
        raise ValueError("Source string is too long for the destination buffer.")
    dest[:len(src)] = src

# Example usage
destination_buffer = [''] * 10  # Simulating a buffer of size 10
source_string = "HelloWorld"  # This is 10 characters long

try:
    safe_strncpy(destination_buffer, source_string, len(destination_buffer))
    print("Buffer after copy:", ''.join(destination_buffer))
except ValueError as e:
    print("Error:", e)