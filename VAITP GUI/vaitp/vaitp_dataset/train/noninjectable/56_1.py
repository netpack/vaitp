import ctypes

def vulnerable_function(user_input):
    # Create a ctypes object
    obj = ctypes.c_double(user_input)

    # Use the PyCArg_repr function, which is vulnerable to buffer overflow
    repr(obj)

# Example usage:
user_input = "1.23456789012345678901234567890"  # Malicious input
vulnerable_function(user_input)