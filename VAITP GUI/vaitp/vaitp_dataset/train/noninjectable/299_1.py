# Vulnerable code that demonstrates the potential backdoor
# by importing an untrusted package that could execute arbitrary code.

import democritus_strings  # This package contains the backdoor

def risky_math_operation(a, b):
    return democritus_strings.some_function(a, b)  # Potentially unsafe operation

# Use the risky function
result = risky_math_operation(5, 3)
print(f"Result of risky math operation: {result}")