def vulnerable_integer_addition(a, b):
    # This function does not check for potential overflow
    return a + b

def vulnerable_integer_multiplication(a, b):
    # This function does not check for potential overflow
    return a * b

# Example usage
result_add = vulnerable_integer_addition(2147483647, 1)  # This may cause an overflow
print(result_add)

result_mul = vulnerable_integer_multiplication(100000, 30000)  # This may also cause an overflow
print(result_mul)