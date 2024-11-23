import tensorflow as tf

# Example of creating a ragged tensor without input validation
def create_ragged_tensor(values, row_splits):
    # No validation of input arguments, which can lead to excessive memory usage
    return tf.ragged.constant(values, row_splits=row_splits)

# Example usage
ragged_tensor = create_ragged_tensor([[1, 2], [3] * 10**6], [0, 2, 2])
print(ragged_tensor)