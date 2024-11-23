import tensorflow as tf
import pybind11

# Vulnerable implementation of to_dlpack
def to_dlpack(obj):
    # This code does not check if 'obj' is a Tensor
    tensor_ptr = pybind11.cast(obj)  # Unsafe cast, assumes obj is a Tensor
    return tensor_ptr

# Example usage that triggers the vulnerability
# Passing a non-tensor object, which could lead to uninitialized memory access
vulnerable_output = to_dlpack("not_a_tensor")  # This could cause memory corruption