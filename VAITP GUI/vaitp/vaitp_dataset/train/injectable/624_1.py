import json

def renderLocalView(data):
    # Instead of using pickle, use json to safely deserialize data
    try:
        # Assuming 'data' is a JSON string that needs to be deserialized
        deserialized_data = json.loads(data)
        # Process the deserialized data safely
        return process_data(deserialized_data)
    except json.JSONDecodeError:
        raise ValueError("Invalid data format")