# Example of a vulnerable contract in Vyper (not actual code, for demonstration only)

msg_data = b"example_data"

@public
def vulnerable_function(start: uint256, length: uint256):
    return msg_data[start:start + length]  # Vulnerable to double eval if start or length have side-effects

# Example of side-effect causing arguments
@public
def side_effect_function() -> uint256:
    return 1  # This function has side-effects

@public
def exploit_function():
    return vulnerable_function(side_effect_function(), side_effect_function())  # Can trigger double eval vulnerability