# Example of a fixed comparison function in Vyper to handle bytestrings correctly

def safe_bytestring_compare(a: bytes, b: bytes) -> bool:
    # Ensure both bytestrings are of equal length before comparing
    if len(a) != len(b):
        return False
    # Perform a word-for-word comparison
    return a == b

# Example usage
a = b"example\x00"
b = b"example"

# This will now return False, correctly handling the comparison
result = safe_bytestring_compare(a, b)