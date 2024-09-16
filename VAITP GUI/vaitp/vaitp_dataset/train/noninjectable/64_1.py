import sys
import ctypes

# Set the Python search path to the current directory
sys.path.append(".")

# Load a DLL file from the current directory
mydll = ctypes.cdll.LoadLibrary("mydll.dll")

# Call a function in the DLL
result = mydll.my_function()