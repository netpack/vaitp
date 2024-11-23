import pickle

# Example of unsafe loading of serialized data
def unsafe_loads(serialized_data):
    # Directly loading the data without any restrictions
    return pickle.loads(serialized_data)

# Example of using the unsafe_loads function
if __name__ == "__main__":
    # Simulated serialized data (could be crafted by an attacker)
    serialized_data = b'...'  # Replace with actual serialized data

    try:
        data = unsafe_loads(serialized_data)
        print("Data loaded successfully:", data)
    except Exception as e:
        print("Failed to load data:", e)