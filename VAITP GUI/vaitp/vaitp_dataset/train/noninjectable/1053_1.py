import numpy as np
import pickle
from sagemaker.base_deserializers import NumpyDeserializer

# Vulnerable code demonstrating unsafe deserialization
def vulnerable_deserialization(pickled_data):
    # Directly unpickling data without validation
    return pickle.loads(pickled_data)

# Example usage with untrusted data
untrusted_data = b"cos\nsystem\n(S'echo Vulnerable!'\n)"  # Malicious payload
pickled_data = pickle.dumps(np.array([1, 2, 3]))

# This could lead to remote code execution
result = vulnerable_deserialization(pickled_data)
print(result)