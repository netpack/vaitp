import tensorflow as tf

# Creating a tensor with a non-numeric type
non_numeric_tensor = tf.constant(['a', 'b', 'c'])

# Attempting to perform a numeric operation on a non-numeric tensor
# This will lead to a TypeError, not a null pointer dereference.
try:
  result = tf.add(non_numeric_tensor, 1)  # This operation is expected to fail
  print(result)
except tf.errors.InvalidArgumentError as e:
  print(f"Error: {e}")
except TypeError as e:
    print(f"Error: {e}")
