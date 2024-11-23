def safe_integer_addition(a, b):
    # Check for potential overflow before performing the addition
    if a > 0 and b > 0 and a > (2**31 - 1) - b:
        raise OverflowError("Integer addition overflow")
    return a + b

def safe_integer_multiplication(a, b):
    # Check for potential overflow before performing the multiplication
    if a > 0 and b > 0 and a > (2**31 - 1) // b:
        raise OverflowError("Integer multiplication overflow")
    return a * b

# Example usage
try:
    result = safe_integer_addition(2147483647, 1)  # This should raise an OverflowError
except OverflowError as e:
    print(e)

try:
    result = safe_integer_multiplication(100000, 30000)  # This should be fine
    print(result)
except OverflowError as e:
    print(e)