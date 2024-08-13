# Vulnerable code example for CVE-2023-33595

import ctypes

# Create a bytes object with a pointer to a freed memory location
b = b'AAAA'
ptr = ctypes.addressof(b)
del b  # Free the memory

# Create a new bytes object and attempt to decode it using ascii_decode
new_b = b'BBBB'
new_b.decode('ascii', errors='strict')  # This will trigger the use-after-free vulnerability

# The following line will likely cause a segmentation fault or crash
print(new_b)