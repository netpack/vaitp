# Example of a vulnerable Vyper-like contract
array_size = 10
my_array = [0] * array_size

def access_array(index: int):
    # Vulnerability: allows negative index
    return my_array[index]

# Example of calling the function with a negative index
value = access_array(-1)  # This would access the last element due to 2's complement representation