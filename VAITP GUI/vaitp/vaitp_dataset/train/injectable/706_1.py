import tensorflow as tf

@tf.function
def func_a():
    return func_b()

@tf.function
def func_b():
    return func_a()

# This will cause a deadlock in vulnerable versions of TensorFlow
try:
    func_a()
except RuntimeError as e:
    print("Caught a RuntimeError, indicating a potential deadlock:", e)

# To demonstrate the fix, we can avoid mutual recursion or use a different approach
# that does not involve `tf.function` for mutually recursive calls.
def safe_func_a():
    return 1  # Base case to prevent recursion

def safe_func_b():
    return 2  # Base case to prevent recursion

# Safe invocation
result_a = safe_func_a()
result_b = safe_func_b()
print("Results:", result_a, result_b)