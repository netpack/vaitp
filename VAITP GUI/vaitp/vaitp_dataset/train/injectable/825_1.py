import os
import ctypes

# Correctly specify the path to the DLL to prevent DLL hijacking
def load_python_dll():
    # Use an absolute path to the trusted DLL location
    trusted_dll_path = r"C:\Python39\python3.dll"  # Update to the correct path of your Python DLL
    if os.path.exists(trusted_dll_path):
        ctypes.WinDLL(trusted_dll_path)
    else:
        raise FileNotFoundError("The specified DLL does not exist.")

# Call the function to load the DLL
load_python_dll()