import pickle

def load_metadata(metadata):
    # Using pickle.loads unsafely, which can lead to remote code execution
    return pickle.loads(metadata)

def save_metadata(metadata):
    # Using pickle.dumps to serialize the metadata
    return pickle.dumps(metadata)

# Example usage
metadata_to_save = {'key': 'value', 'another_key': 123}
serialized_metadata = save_metadata(metadata_to_save)

# This line is vulnerable to remote code execution if serialized_metadata is crafted
loaded_metadata = load_metadata(serialized_metadata)

print(loaded_metadata)