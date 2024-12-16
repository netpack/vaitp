def safe_shift(value, shift):
    # Cap the shift exponent to prevent out-of-bounds shift
    max_shift = (value.bit_length() - 1)  # Maximum allowed shift based on the value's bit length
    if shift < 0 or shift >= max_shift:
        raise ValueError("Shift out of bounds")
    return value >> shift

# Example usage
try:
    result = safe_shift(100, 10)  # This will work
    print(result)
    
    result = safe_shift(100, 100)  # This will raise an error
except ValueError as e:
    print(e)