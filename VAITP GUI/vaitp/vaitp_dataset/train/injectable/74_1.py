import os
import ctypes

# Specify the full path to the DLL file to load
dll_path = os.path.join(os.environ['SYSTEMROOT'], 'system32', 'user32.dll')

# Load the DLL file using the full path
ctypes.CDLL(dll_path)