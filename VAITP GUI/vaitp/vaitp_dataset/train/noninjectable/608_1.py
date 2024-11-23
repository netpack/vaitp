import pickle

# Example of unsafe deserialization using pickle
def load_data(serialized_data):
    # This is vulnerable to arbitrary code execution
    return pickle.loads(serialized_data)

# Example of serializing data
def dump_data(data):
    return pickle.dumps(data)

# Usage
serialized_data = dump_data({'key': 'value'})
deserialized_data = load_data(serialized_data)
print(deserialized_data)