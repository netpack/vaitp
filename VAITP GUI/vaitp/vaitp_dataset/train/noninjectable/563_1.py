import numpy as np

# Loading a .npy file using numpy's load function with allow_pickle set to True
# This demonstrates the vulnerability as it allows arbitrary code execution
def vulnerable_load(file_path):
    return np.load(file_path, allow_pickle=True)

# Example usage
# array = vulnerable_load('data.npy')