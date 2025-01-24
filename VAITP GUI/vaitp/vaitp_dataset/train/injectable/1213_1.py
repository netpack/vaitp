# Example of a safe contract in Vyper (not actual code, for demonstration only)
msg_data = b"example_data"

# Fixed version using a safe approach
@public
def safe_function(start: uint256, length: uint256):
    _start = start
    _length = length
    assert _start + _length <= len(msg_data), "Out of bounds"
    return msg_data[_start:_start + _length]  # No side-effects in arguments