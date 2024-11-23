import ctypes
import os

def listxattr_vulnerable(path, size):
    # Simulate the behavior of listxattr without proper buffer size checks
    if size < 0:
        raise ValueError("Size must be non-negative")

    # Simulated return size of attributes
    actual_size = 16  # This would be the size required for attributes

    if size == 0:
        return actual_size  # Return the required size for the buffer

    # Vulnerable behavior: does not check if actual_size exceeds provided size
    buffer = ctypes.create_string_buffer(size)
    # Simulate filling the buffer (this could lead to a buffer overflow if actual_size > size)
    buffer.value = b'system.nfs4_acl'  # Example attribute name

    return buffer.raw  # Return the filled buffer

# Example usage
try:
    path = "/some/path"
    size = 16  # Example buffer size
    result = listxattr_vulnerable(path, size)
    print("Attributes:", result)
except OSError as e:
    print("Error:", e)
except ValueError as ve:
    print("Value Error:", ve)