import pickle

# Example of potentially unsafe deserialization using pickle
data = b"cos\nsystem\n(S'echo vulnerable'\n."  # This simulates a malicious payload

# Deserializing the data, which can lead to arbitrary command execution
result = pickle.loads(data)