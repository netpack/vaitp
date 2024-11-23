import json

# Example of a safe deserialization method
def safe_load(data):
    try:
        # Use json instead of pickle for safe deserialization
        return json.loads(data)
    except json.JSONDecodeError as e:
        print("Error decoding JSON:", e)
        return None

# Example of serializing data safely
def safe_dump(data):
    return json.dumps(data)

# Usage
serialized_data = safe_dump({'key': 'value'})
deserialized_data = safe_load(serialized_data)
print(deserialized_data)