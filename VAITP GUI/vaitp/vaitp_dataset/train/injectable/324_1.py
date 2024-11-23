# Example of a fixed version of the d8s-stats package
# The vulnerability was due to executing untrusted code. 
# Here, we ensure that no untrusted code is executed.

import math

def safe_calculate(value):
    # Perform a safe calculation without executing any untrusted code
    if isinstance(value, (int, float)):
        return math.sqrt(value)  # Example of a safe operation
    else:
        raise ValueError("Input must be a number.")

# Example usage
try:
    result = safe_calculate(16)
    print("Safe calculation result:", result)
except ValueError as e:
    print("Error:", e)