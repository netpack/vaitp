# Import the ctypes module
import ctypes

# Define a function that checks the validity of the argument
# This function returns True if the argument is a finite floating-point number
# It returns False otherwise
def check_param(arg):
    return isinstance(arg, float) and arg.isfinite()

# Define a malicious floating-point number
# This number is large enough to trigger the buffer overflow
number = 1e300

# Try to convert the number to a C double using the ctypes module
# Pass the check_param argument to the from_param function
try:
    ctypes.c_double.from_param(number, check_param=check_param)
    # Do something with the C double
except TypeError as e:
    # Handle the exception
    print(e)