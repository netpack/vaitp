import numpy as np
import os

# Securely loading a .npy file without using pickle
def secure_load(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError("The specified file does not exist.")
    
    # Load the array from a .npy file using numpy's built-in load function
    # with allow_pickle set to False to prevent arbitrary code execution
    return np.load(file_path, allow_pickle=False)

# Example usage
# array = secure_load('data.npy')