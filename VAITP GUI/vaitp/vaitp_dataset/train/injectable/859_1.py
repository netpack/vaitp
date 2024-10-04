import numpy as np

def create_safe_array(dimensions):
    MAX_DIMENSIONS = 32  # Setting a maximum allowed dimensions
    
    if len(dimensions) > MAX_DIMENSIONS:
        raise ValueError(f"Cannot create an array with more than {MAX_DIMENSIONS} dimensions for safety reasons.")
    
    return np.zeros(dimensions)

# Example Usage
try:
    # Attempting to create an array within the safe limit
    safe_array = create_safe_array(tuple([2] * 10))  # This should work
    print("Safe array created successfully:", safe_array.shape)

    # Attempting to create an array exceeding the safe limit
    unsafe_array = create_safe_array(tuple([2] * 33))  # This should raise an exception
except ValueError as e:
    print("Safety check triggered:", e)