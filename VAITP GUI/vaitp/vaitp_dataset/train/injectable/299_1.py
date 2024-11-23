# Fixed version of the code that avoids the vulnerability
# by not importing or executing any untrusted packages.

def safe_math_operation(a, b):
    return a + b  # Example of a safe operation

# Use the safe function
result = safe_math_operation(5, 3)
print(f"Result of safe math operation: {result}")