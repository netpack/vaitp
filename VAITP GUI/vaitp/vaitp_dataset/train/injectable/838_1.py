import tensorflow as tf

def safe_quantized_batch_norm_with_global_normalization(input_tensor, scale, offset, mean, variance, epsilon=1e-5):
    # Validate inputs to prevent division by zero
    if tf.reduce_any(variance <= 0):
        raise ValueError("Variance must be greater than zero to avoid division by zero.")

    # Proceed with the quantized batch normalization operation
    return tf.raw_ops.QuantizedBatchNormWithGlobalNormalization(
        input=input_tensor,
        scale=scale,
        offset=offset,
        mean=mean,
        variance=variance,
        epsilon=epsilon
    )

# Example usage
try:
    input_tensor = tf.constant([1, 2, 3], dtype=tf.qint8)
    scale = tf.constant([1.0], dtype=tf.float32)
    offset = tf.constant([0.0], dtype=tf.float32)
    mean = tf.constant([1.0], dtype=tf.float32)
    variance = tf.constant([0.0], dtype=tf.float32)  # This will trigger the validation

    result = safe_quantized_batch_norm_with_global_normalization(input_tensor, scale, offset, mean, variance)
except ValueError as e:
    print(e)