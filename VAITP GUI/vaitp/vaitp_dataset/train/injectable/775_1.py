import pyarrow as pa

def create_array_with_nulls(data):
    # Ensure that the data is initialized properly
    # Fill in uninitialized memory to avoid sharing uninitialized values
    initialized_data = [value if value is not None else 0 for value in data]  # Replace None with a default value
    array = pa.array(initialized_data, mask=[value is None for value in data])
    return array

# Example usage
data = [1, None, 3, None, 5]
array_with_nulls = create_array_with_nulls(data)
print(array_with_nulls)