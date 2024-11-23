import re

def safe_compile(pattern):
    # Check for overly large quantifier values
    if re.search(r'(\d+|\d+\s*,\s*\d*)\s*\{(\d+),(\d+)\}', pattern):
        raise ValueError("Quantifier values are too large or malformed.")
    
    return re.compile(pattern)

# Example usage
try:
    regex = safe_compile(r'a{1,1000000000}')  # This would raise an error
except ValueError as e:
    print(e)