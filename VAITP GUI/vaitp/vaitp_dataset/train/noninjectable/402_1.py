# Example demonstrating the vulnerability in Vyper with side effects
# This code represents the vulnerability before it was fixed

# Vulnerable code
def vulnerable_function(a, b):
    # Side effect: modifying a global variable
    global side_effect_var
    side_effect_var = a + 1  # This side effect can affect other arguments
    return uint256_addmod(a, side_effect_var, 10)  # Dependent on side effect