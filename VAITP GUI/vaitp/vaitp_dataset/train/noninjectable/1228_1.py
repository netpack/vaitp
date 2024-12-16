def vulnerable_mpz_as_bytes(value):
    # Vulnerable implementation that does not handle zero properly
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')

# Example usage that could trigger the vulnerability
try:
    print(vulnerable_mpz_as_bytes(0))  # This could lead to a buffer overflow
except Exception as e:
    print(e)