import os
import ctypes

def load_library(library_name):
    # Load the library directly from the current working directory
    return ctypes.CDLL(library_name)

# Example usage
try:
    my_library = load_library("my_library.dll")
except Exception as e:
    print(f"Error: {e}")