# Example of a vulnerable contract in Vyper (not actual code, for demonstration only)

# Assume this is a simplified representation of the vulnerable behavior
msg_data = b"example_data"

@public
def vulnerable_function(start: uint256, length: uint256):
    return msg_data[start:start + length]  # Vulnerable to double eval if start or length have side-effects

# Fixed version using a safe approach
@public
def safe_function(start: uint256, length: uint256):
    assert start + length <= len(msg_data), "Out of bounds"
    return msg_data[start:start + length]  # No side-effects in arguments