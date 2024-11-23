import tensorflow as tf

# Creating a tensor with a non-numeric type
non_numeric_tensor = tf.constant(['a', 'b', 'c'])

# Attempting to perform a numeric operation on a non-numeric tensor
# This will lead to a null pointer dereference vulnerability
result = tf.add(non_numeric_tensor, 1)  # This operation is expected to fail
print(result)