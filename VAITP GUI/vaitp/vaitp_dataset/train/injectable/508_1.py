import json

# Define a safe loading function that restricts the types that can be deserialized
def safe_loads(serialized_data):
    # Use a safe alternative to load the data
    return json.loads(serialized_data)

# Example of using the safe_loads function
if __name__ == "__main__":
    # Simulated serialized data (this should come from a trusted source)
    serialized_data = b'{"key": "value"}'  # Replace with actual serialized data

    try:
        data = safe_loads(serialized_data.decode('utf-8'))
        print("Data loaded successfully:", data)
    except Exception as e:
        print("Failed to load data:", e)