import tensorflow as tf

# Example of the vulnerability in TensorFlow versions before the fix
value = tf.constant("hello", dtype=tf.float16)