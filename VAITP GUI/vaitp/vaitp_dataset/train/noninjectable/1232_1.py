import os
import ctypes

# Potentially unsafe loading of Shcore.dll from the PATH
def load_shcore():
    ctypes.WinDLL("Shcore.dll")

load_shcore()