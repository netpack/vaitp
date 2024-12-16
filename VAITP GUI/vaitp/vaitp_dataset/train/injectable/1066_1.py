# Example of a vulnerable Vyper-like contract
array_size = 10
my_array = [0] * array_size

# Fixed version of the function
def access_array_fixed(index: int):
    if index < 0:
        raise ValueError("Index must be a non-negative integer.")
    return my_array[index]

# Example of calling the function with a negative index
value = access_array(-1)  # This would try to access the last element due to 2's complement representation
