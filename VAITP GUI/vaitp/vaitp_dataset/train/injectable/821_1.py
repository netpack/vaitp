import tensorflow as tf

# Example of creating a ragged tensor with input validation
def create_ragged_tensor(values, row_splits):
    # Validate input arguments to prevent excessive memory consumption
    if not isinstance(values, (list, tuple)):
        raise ValueError("Values must be a list or tuple.")
    if not isinstance(row_splits, (list, tuple)):
        raise ValueError("Row splits must be a list or tuple.")
    
    # Create a ragged tensor
    return tf.ragged.constant(values, row_splits=row_splits)

# Example usage
try:
    ragged_tensor = create_ragged_tensor([[1, 2], [3]], [0, 2, 2])
    print(ragged_tensor)
except ValueError as e:
    print(f"Error: {e}")