# Example demonstrating the vulnerability in MicroPython 1.22.2

# Vulnerable code (simulated)
def vulnerable_bytes_manipulation():
    data = bytearray(b"initial data")
    # Resizing and copying into itself, which may lead to use after free
    data = data[:10]  # Simulate resizing
    data[0:10] = data  # Potentially problematic operation
    return data

# Fixed code (simulated)
def fixed_bytes_manipulation():
    data = bytearray(b"initial data")
    # Properly handling resizing without self-referencing
    temp_data = data[:10]  # Create a temporary copy
    data[0:10] = temp_data  # Safe assignment
    return data