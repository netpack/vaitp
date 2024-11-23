import tensorflow as tf

def reverse_sequence_with_validation(input_tensor, seq_lengths, batch_dim):
    # Validate batch_dim
    if batch_dim < 0:
        raise ValueError("batch_dim must be non-negative")
    
    # Get the rank of the input tensor
    input_rank = tf.rank(input_tensor)
    
    # Validate that batch_dim does not exceed the rank of the input tensor
    if batch_dim >= input_rank:
        raise ValueError("batch_dim exceeds the rank of the input tensor")

    # Perform reverse sequence operation
    return tf.reverse_sequence(input_tensor, seq_lengths, seq_axis=batch_dim)

# Example usage
input_tensor = tf.constant([[1, 2, 3], [4, 5, 6]])
seq_lengths = tf.constant([2, 3])
batch_dim = 0  # This is valid

output = reverse_sequence_with_validation(input_tensor, seq_lengths, batch_dim)
print(output)