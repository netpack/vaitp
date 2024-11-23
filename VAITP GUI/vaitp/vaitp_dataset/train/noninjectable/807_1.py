import ctypes

# Attempt to load the DLL without specifying a full path
# This could lead to loading a malicious DLL from an uncontrolled path
ctypes.CDLL("C:\\DLLs\\python3.dll")