import tensorflow as tf

# This function demonstrates the vulnerability by directly passing an invalid token
def vulnerable_py_func(token):
    # No check for UTF-8 bytestring, leading to potential CHECK fail
    return tf.raw_ops.PyFunc(func='your_function', inp=[token], Tout=tf.float32)

# Example usage with an invalid token
invalid_token = b'\x80\x81'  # Invalid UTF-8 bytes
result = vulnerable_py_func(invalid_token)