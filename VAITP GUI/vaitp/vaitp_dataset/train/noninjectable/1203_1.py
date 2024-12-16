def unsafe_strncpy(dest, src):
    # This function does not check the length of src before copying
    for i in range(len(src)):
        dest[i] = src[i]  # Potential out-of-bounds write if src is too long

# Example usage
destination_buffer = [''] * 10  # Simulating a buffer of size 10
source_string = "This string is definitely longer than the destination buffer"

unsafe_strncpy(destination_buffer, source_string)
print("Buffer after copy:", ''.join(destination_buffer))