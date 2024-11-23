import tensorflow as tf

def safe_composite_tensor_variant_to_components(encoded):
    if not isinstance(encoded, tf.Tensor) or encoded.dtype != tf.variant:
        raise ValueError("Input must be a valid CompositeTensorVariant tensor.")
    
    return tf.raw_ops.CompositeTensorVariantToComponents(encoded)

# Example usage
try:
    # This will raise an error if 'encoded' is not a valid CompositeTensorVariant
    components = safe_composite_tensor_variant_to_components(encoded)
except ValueError as e:
    print(e)