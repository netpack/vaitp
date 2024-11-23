import pickle

def load_data(serialized_data):
    # Vulnerable deserialization of untrusted data
    return pickle.loads(serialized_data)

# Example usage
try:
    with open("data.pkl", "rb") as f:
        data = load_data(f.read())
except Exception as e:
    print(f"Error loading data: {e}")