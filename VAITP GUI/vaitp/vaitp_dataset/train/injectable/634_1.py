import json
import os

def safe_load_metadata(xattrs):
    # Instead of using pickle, which is unsafe, we use json to load metadata
    metadata = {}
    for key, value in xattrs.items():
        if key.startswith('user.'):
            try:
                # Assuming the metadata is stored as JSON strings
                metadata[key] = json.loads(value)
            except json.JSONDecodeError:
                # Handle the case where the JSON is invalid
                continue
    return metadata

# Example usage
xattrs = {
    'user.metadata': '{"key1": "value1", "key2": "value2"}'
}

metadata = safe_load_metadata(xattrs)
print(metadata)