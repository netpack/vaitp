import os
import ctypes

# Safe loading of Shcore.dll from a trusted directory
def load_shcore():
    trusted_path = r"C:\Path\To\Trusted\Directory\Shcore.dll"
    if os.path.exists(trusted_path):
        ctypes.WinDLL(trusted_path)
    else:
        raise FileNotFoundError("Trusted Shcore.dll not found.")

load_shcore()