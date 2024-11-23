import json

def safe_load(data):
    # Use json instead of pickle to safely deserialize data
    return json.loads(data)

# Example of using the safe_load function
def process_data(serialized_data):
    try:
        data = safe_load(serialized_data)
        # Process the data as needed
    except json.JSONDecodeError:
        print("Invalid data format")