import pickle

# Vulnerable code example using unpickle
def vulnerable_load_data(data):
    return pickle.loads(data)

# Fixed code example that avoids using unpickle
def safe_load_data(data):
    # Instead of unpickling, use a safer method to deserialize data
    # Here we assume data is a dictionary and we validate it
    if isinstance(data, dict):
        # Perform further validation on the dictionary if needed
        return data
    else:
        raise ValueError("Invalid data format")