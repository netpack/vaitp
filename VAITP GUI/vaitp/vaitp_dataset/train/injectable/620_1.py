import tensorflow as tf
import numpy as np

def safe_py_func(token):
    # Ensure the input token is a valid UTF-8 bytestring
    if not isinstance(token, bytes) or not token.decode('utf-8', errors='ignore'):
        raise ValueError("Input token must be a valid UTF-8 bytestring.")
    
    # Define a simple function for the PyFunc operation
    def your_function(token_bytes):
        token_str = token_bytes.decode('utf-8')
        return np.array(len(token_str), dtype=np.float32)


    # Proceed with the PyFunc operation
    return tf.raw_ops.PyFunc(func=your_function, inp=[token], Tout=tf.float32)

# Example usage
try:
    result = safe_py_func(b'valid_utf8_token')
    print(result)
except ValueError as e:
    print(e)