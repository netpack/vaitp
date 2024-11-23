def resolve_axis(axis, tensor_shape):
    if axis < 0:
        axis += len(tensor_shape)
    # No check for valid index in non-debug builds
    return axis

# Example usage
tensor_shape = [3, 4, 5]
axis = -1  # Example of negative indexing
resolved_axis = resolve_axis(axis, tensor_shape)
# This could lead to accessing out of bounds
print(f"Resolved axis: {resolved_axis}")
print(f"Accessing tensor at resolved axis: {tensor_shape[resolved_axis]}")