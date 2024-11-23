import tensorflow as tf

def safe_immutable_const(value, dtype):
    # Check if dtype is tf.resource or tf.variant
    if dtype in [tf.resource, tf.variant]:
        raise ValueError("Invalid dtype: tf.resource or tf.variant is not allowed.")
    return tf.raw_ops.ImmutableConst(value=value, dtype=dtype)

# Example usage
try:
    # This will raise an error
    tensor = safe_immutable_const(value=[1, 2, 3], dtype=tf.resource)
except ValueError as e:
    print(e)