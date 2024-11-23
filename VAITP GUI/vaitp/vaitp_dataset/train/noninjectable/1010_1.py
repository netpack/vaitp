# This code demonstrates the vulnerability in Vyper prior to version 0.3.8
# where default arguments are compiled incorrectly.

@public
def vulnerable_function(arg1: int, arg2: int = 10, arg3: int = 20) -> int:
    return arg1 + arg2 + arg3

# Incorrectly calling the function with only one argument
result = vulnerable_function(5)  # This may lead to unexpected behavior
# result could incorrectly compute using left-to-right instead of right-to-left
# resulting in an unexpected sum if types are not compatible