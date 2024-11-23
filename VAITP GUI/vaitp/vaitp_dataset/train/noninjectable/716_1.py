import tensorflow as tf

# Simulating the vulnerability in tf.keras.losses.poisson
def vulnerable_poisson_loss(y_true, y_pred):
    # This function does not check for dimension overflow
    return tf.keras.losses.poisson(y_true, y_pred)

# Example usage with large dimensions
y_true = tf.random.uniform((100000, 100000), minval=0, maxval=10)
y_pred = tf.random.uniform((100000, 100000), minval=0, maxval=10)

# This may cause TensorFlow to crash due to size mismatch
try:
    loss = vulnerable_poisson_loss(y_true, y_pred)
    print("Loss:", loss.numpy())
except Exception as e:
    print("Error:", e)