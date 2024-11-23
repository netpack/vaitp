import ctypes
import os

def listxattr_safe(path, size):
    # Simulate the behavior of listxattr with buffer size checks
    if size < 0:
        raise ValueError("Size must be non-negative")

    # Simulate the call to listxattr
    # Here we would normally call a C function via ctypes
    # For demonstration, we simulate the return value
    actual_size = 16  # Simulated size of attributes

    if size == 0:
        return actual_size  # Return the required size for the buffer

    if actual_size > size:
        raise OSError("ERANGE: Buffer size too small")

    # Simulate filling the buffer
    buffer = ctypes.create_string_buffer(size)
    # Normally, we would fill the buffer with the attribute names here

    return buffer.raw  # Return the filled buffer

# Example usage
try:
    path = "/some/path"
    size = 16  # Example buffer size
    result = listxattr_safe(path, size)
    print("Attributes:", result)
except OSError as e:
    print("Error:", e)
except ValueError as ve:
    print("Value Error:", ve)