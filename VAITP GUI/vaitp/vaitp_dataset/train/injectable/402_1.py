# Example demonstrating the vulnerability in Vyper with side effects
# This code is meant to represent the vulnerability, not the fix

# Vulnerable code
def vulnerable_function(a, b):
    # Side effect: modifying a global variable
    global side_effect_var
    side_effect_var = a + 1
    return uint256_addmod(a, b, 10)

# Corrected code to avoid side effects in arguments
def fixed_function(a, b):
    # Avoid side effects in arguments
    temp_a = a + 1  # Compute side effect separately
    return uint256_addmod(temp_a, b, 10)