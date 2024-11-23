import pyarrow as pa

def create_array_with_nulls(data):
    # This code does not properly initialize memory for null values
    # Potentially leading to uninitialized memory being shared
    array = pa.array(data, mask=[value is None for value in data])
    return array

# Example usage
data = [1, None, 3, None, 5]
array_with_nulls = create_array_with_nulls(data)
print(array_with_nulls)