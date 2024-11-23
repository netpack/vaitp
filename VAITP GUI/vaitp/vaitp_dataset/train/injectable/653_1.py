import tensorflow as tf
import pybind11

# Simulating the vulnerability
def unsafe_to_dlpack(obj):
    # This simulates the unsafe behavior of assuming 'obj' is a Tensor
    if not isinstance(obj, tf.Tensor):
        raise TypeError("Expected a Tensor, got: {}".format(type(obj)))
    
    # Simulated reinterpret_cast that could lead to uninitialized memory access
    tensor_ptr = pybind11.cast(obj)
    return tensor_ptr

# Example usage that would trigger the vulnerability
try:
    unsafe_to_dlpack("not_a_tensor")  # Passing a string instead of a Tensor
except TypeError as e:
    print(e)

# Fixing the vulnerability
def safe_to_dlpack(obj):
    # Check if the input is a Tensor before proceeding
    if not isinstance(obj, tf.Tensor):
        raise TypeError("Expected a Tensor, got: {}".format(type(obj)))

    # Safe conversion to dlpack
    tensor_ptr = pybind11.cast(obj)
    return tensor_ptr

# Example usage with the fix
try:
    safe_to_dlpack("not_a_tensor")  # This will now raise a TypeError
except TypeError as e:
    print(e)