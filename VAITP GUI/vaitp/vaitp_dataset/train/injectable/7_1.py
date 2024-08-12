# Non-vulnerable code example for CVE-2023-33595

import ctypes

# Create a bytes object
b = b'AAAA'

# Create a new bytes object and attempt to decode it using ascii_decode
new_b = b'BBBB'
new_b.decode('ascii', errors='strict')  # This is safe because we didn't free any memory

# The following line will print the decoded bytes object
print(new_b)