def abi_decode(data, start_index, length):
    # Vulnerable code that does not check for index overflow
    return data[start_index:start_index + length]

# Example usage
data = [1, 2, 3, 4, 5]
start_index = 2**32  # Excessively large index that can cause overflow
length = 3
decoded_values = abi_decode(data, start_index, length)
print(decoded_values)  # This may lead to unintended behavior or errors