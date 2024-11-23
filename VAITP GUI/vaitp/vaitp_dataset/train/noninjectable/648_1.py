import pickle

def handle_data(input_data):
    try:
        # Directly unpickling data from an untrusted source
        data = pickle.loads(input_data)  # Vulnerable code
        # Process the data
    except Exception as e:
        # Handle exceptions appropriately
        print("Error processing data:", e)

# Example usage
# input_data = ...  # This would be the incoming pickled data
# handle_data(input_data)