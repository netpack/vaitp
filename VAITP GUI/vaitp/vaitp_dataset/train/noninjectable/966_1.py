import tensorflow as tf

def reverse_sequence(input_tensor, seq_lengths, batch_dim):
    # No validation for negative batch_dim
    # Get the rank of the input tensor
    input_rank = tf.rank(input_tensor)
    
    # Check that batch_dim does not exceed the rank of the input tensor
    if batch_dim >= input_rank:
        raise ValueError("batch_dim exceeds the rank of the input tensor")

    # Perform reverse sequence operation without proper validation
    return tf.reverse_sequence(input_tensor, seq_lengths, seq_axis=batch_dim)

# Example usage
input_tensor = tf.constant([[1, 2, 3], [4, 5, 6]])
seq_lengths = tf.constant([2, 3])
batch_dim = -1  # This can lead to an out-of-bounds read

output = reverse_sequence(input_tensor, seq_lengths, batch_dim)
print(output)