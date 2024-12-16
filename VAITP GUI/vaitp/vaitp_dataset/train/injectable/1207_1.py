# Example of a safe implementation of extract32 in Vyper

def safe_extract32(b: bytes, start: int) -> bytes:
    # Ensure that the start index is valid and does not modify the original byte array
    assert start >= 0 and start + 32 <= len(b), "Invalid start index"
    return b[start:start + 32]