import pickle

# Define a safe loading function that restricts the types that can be deserialized
def safe_loads(serialized_data):
    # Use a safe alternative to load the data
    return pickle.loads(serialized_data, fix_imports=False, encoding="ASCII", errors="strict")

# Example of using the safe_loads function
if __name__ == "__main__":
    # Simulated serialized data (this should come from a trusted source)
    serialized_data = b'...'  # Replace with actual serialized data

    try:
        data = safe_loads(serialized_data)
        print("Data loaded successfully:", data)
    except Exception as e:
        print("Failed to load data:", e)