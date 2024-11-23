# Example of a vulnerable concat function in Vyper (not actual code, for demonstration purposes)
@public
@pure
def vulnerable_concat(a: bytes, b: bytes) -> bytes:
    return concat(a, b)  # This can lead to a buffer overflow