import os
import ctypes

# Specify the full path to the DLL to prevent DLL hijacking
dll_path = r"C:\Program Files\Rapid7\Insight Agent\python3.dll"

# Check if the DLL exists at the specified path
if os.path.exists(dll_path):
    # Load the DLL using the full path
    ctypes.CDLL(dll_path)
else:
    raise FileNotFoundError("The specified DLL does not exist.")