# Example of a vulnerable comparison function in Vyper that does not handle bytestrings correctly

def vulnerable_bytestring_compare(a: bytes, b: bytes) -> bool:
    # Directly compare the bytestrings without checking their lengths
    return a == b

# Example usage
a = b"example\x00"
b = b"example"

# This will incorrectly return True, demonstrating the vulnerability
result = vulnerable_bytestring_compare(a, b)