def resolve_axis(axis, tensor_shape):
    if axis < 0:
        axis += len(tensor_shape)
    if axis < 0 or axis >= len(tensor_shape):
        raise IndexError("Axis index out of bounds")
    return axis

# Example usage
tensor_shape = [3, 4, 5]
axis = -1  # Example of negative indexing
try:
    resolved_axis = resolve_axis(axis, tensor_shape)
    print(f"Resolved axis: {resolved_axis}")
except IndexError as e:
    print(e)