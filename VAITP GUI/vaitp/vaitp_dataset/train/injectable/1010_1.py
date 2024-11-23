# This code demonstrates the fix for CVE-2023-32059 in Vyper.
# It represents a simple smart contract with proper handling of default arguments.

# Fixed version of the contract ensuring correct handling of default arguments
# and preventing type checking bypass.

@public
def my_function(arg1: int, arg2: int = 10, arg3: int = 20) -> int:
    return arg1 + arg2 + arg3

# Properly calling the function with default arguments
result = my_function(5)  # Should use default values for arg2 and arg3
# result will be 5 + 10 + 20 = 35

# Calling the function with all arguments
result_with_all_args = my_function(5, 15, 25)  # Should use provided values
# result_with_all_args will be 5 + 15 + 25 = 45