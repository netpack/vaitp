# Import the ctypes module
import ctypes

# Define a malicious floating-point number
# This number is large enough to trigger the buffer overflow
number = 1e300

# Try to convert the number to a C double using the ctypes module
# This will cause a segmentation fault due to the vulnerability
ctypes.c_double.from_param(number)