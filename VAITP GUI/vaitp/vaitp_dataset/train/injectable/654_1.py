import tensorflow as tf

# Example of creating a tensor with a non-numeric type
# This can lead to the vulnerability CVE-2021-29513
non_numeric_tensor = tf.constant(['a', 'b', 'c'])

# Attempting to perform a numeric operation on a non-numeric tensor
try:
    result = tf.add(non_numeric_tensor, 1)  # This should raise an error
except Exception as e:
    print(f"Error encountered: {e}")

# To fix the vulnerability, ensure that the tensor is of a numeric type before performing operations
numeric_tensor = tf.constant([1.0, 2.0, 3.0])  # Use numeric values
result_fixed = tf.add(numeric_tensor, 1)  # This will work correctly
print(f"Fixed result: {result_fixed.numpy()}")