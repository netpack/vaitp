import pickle

def load_data(serialized_data):
    # Unsafe deserialization using pickle
    return pickle.loads(serialized_data)

# Example of using the load_data function
def process_data(serialized_data):
    try:
        data = load_data(serialized_data)
        # Process the data as needed
    except Exception as e:
        print(f"Error processing data: {e}")