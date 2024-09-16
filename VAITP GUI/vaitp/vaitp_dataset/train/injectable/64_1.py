import sys
import ctypes

# Set the Python search path to a specific, trusted directory
sys.path.insert(0, r"C:\Python27")

# Load a DLL file from the specified directory
mydll = ctypes.cdll.LoadLibrary(r"C:\Python27\mydll.dll")

# Call a function in the DLL
result = mydll.my_function()