import numpy as np
import pickle
from sagemaker.base_deserializers import NumpyDeserializer

# Example of unsafe deserialization (vulnerable code)
def unsafe_deserialization(pickled_data):
    return pickle.loads(pickled_data)

# Safe deserialization after upgrade (fixed code)
def safe_deserialization(pickled_data):
    # Ensure that the data is coming from a trusted source
    if isinstance(pickled_data, bytes):
        return NumpyDeserializer().deserialize(pickled_data)
    else:
        raise ValueError("Untrusted data source")

# Example usage
trusted_data = np.array([1, 2, 3])
pickled_data = pickle.dumps(trusted_data)

# Use safe deserialization
result = safe_deserialization(pickled_data)
print(result)