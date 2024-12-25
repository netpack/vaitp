import tensorflow as tf

def safe_decode_raw(input_data, fixed_length, dtype):
    # Determine the size of the data type
    type_size = tf.dtypes.as_dtype(dtype).itemsize
    
    # Calculate the number of elements based on the fixed_length
    num_elements = fixed_length // type_size
    
    # Ensure we do not read beyond the input data
    output_data = tf.io.decode_raw(input_data, dtype)
    
    # Correctly slice the output data to avoid out-of-bounds access
    return output_data[:num_elements]

# Example usage
input_data = tf.io.encode_raw(tf.constant([1, 2, 3, 4], dtype=tf.int32), 'int32')  # Example input
fixed_length = 16  # Example fixed length
decoded_output = safe_decode_raw(input_data, fixed_length, tf.int32)

print(decoded_output)