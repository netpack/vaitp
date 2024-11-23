import json

def safe_load_metadata(metadata):
    # Instead of using pickle.loads, we use json.loads for safety
    return json.loads(metadata)

def save_metadata(metadata):
    # Use json.dumps to serialize the metadata safely
    return json.dumps(metadata)

# Example usage
metadata_to_save = {'key': 'value', 'another_key': 123}
serialized_metadata = save_metadata(metadata_to_save)
loaded_metadata = safe_load_metadata(serialized_metadata)

print(loaded_metadata)