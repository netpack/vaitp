# Example of a vulnerable function in Vyper (not actual Vyper code, for demonstration purposes only)

# Vulnerable function that does not clamp bytes length
@public
def vulnerable_function(data: bytes):
    # This could lead to a buffer overrun if `data` is too long
    some_buffer: bytes[32]
    some_buffer = data  # No length check

# Fixed version that clamps bytes length
@public
def fixed_function(data: bytes):
    # Clamp the length of `data` to prevent buffer overrun
    clamped_data: bytes[32]
    clamped_data = data[:32]  # Ensure data is at most 32 bytes