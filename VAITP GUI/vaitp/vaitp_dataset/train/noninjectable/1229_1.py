# Example demonstrating the vulnerability in MicroPython 1.22.2

def vulnerable_bytes_manipulation():
    data = bytearray(b"initial data")
    # Resizing and copying into itself, which may lead to use after free
    data = data[:10]  # Simulate resizing
    data[0:10] = data  # Potentially problematic operation
    return data

# Calling the vulnerable function
result = vulnerable_bytes_manipulation()
print(result)