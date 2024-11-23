import os
import ctypes

# Vulnerable code that does not specify a secure path for loading the DLL
def load_python_dll():
    # This code attempts to load python3.dll from a writable directory
    dll_path = r"C:\DLLs\python3.dll"
    if os.path.exists(dll_path):
        ctypes.WinDLL(dll_path)
    else:
        raise FileNotFoundError("The specified DLL does not exist.")

# Call the function to load the DLL
load_python_dll()