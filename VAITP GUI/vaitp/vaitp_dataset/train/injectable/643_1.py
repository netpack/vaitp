import json

def safe_load(data):
    # Use json instead of pickle to safely deserialize data
    return json.loads(data)

# Example of how to use the safe_load function
def handle_request(serialized_data):
    try:
        # Deserialize the data safely
        data = safe_load(serialized_data)
        # Process the data
        print("Data processed:", data)
    except json.JSONDecodeError as e:
        print("Invalid data:", e)

# Example of a crafted serialized object (in JSON format)
crafted_data = '{"key": "value"}'
handle_request(crafted_data)