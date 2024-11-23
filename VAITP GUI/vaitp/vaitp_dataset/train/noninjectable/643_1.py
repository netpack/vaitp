import pickle

def load_data(serialized_data):
    # Unsafe deserialization using pickle
    return pickle.loads(serialized_data)

# Example of how to use the load_data function
def handle_request(serialized_data):
    try:
        # Deserialize the data unsafely
        data = load_data(serialized_data)
        # Process the data
        print("Data processed:", data)
    except Exception as e:
        print("Error processing data:", e)

# Example of a crafted serialized object (this would be a pickle object)
crafted_data = b'\x80\x03}q\x00X\x03\x00\x00\x00keyq\x01X\x05\x00\x00\x00valueq\x02.'
handle_request(crafted_data)