# Example of a vulnerable function in Vyper (not actual Vyper code, for demonstration purposes only)

@public
def vulnerable_function(data: bytes):
    # This could lead to a buffer overrun if `data` is too long
    some_buffer: bytes[32]
    some_buffer = data  # No length check, directly assigning potentially unsafe data