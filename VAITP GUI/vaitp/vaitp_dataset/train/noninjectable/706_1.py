import tensorflow as tf

@tf.function
def func_a():
    return func_b()

@tf.function
def func_b():
    return func_a()

# This will cause a deadlock in affected versions of TensorFlow
try:
    func_a()
except RuntimeError as e:
    print("Caught a RuntimeError, indicating a potential deadlock:", e)

# Attempting to invoke the mutually recursive functions
func_a()