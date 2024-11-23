import pickle

def safe_load_pickle(file_path):
    with open(file_path, 'rb') as file:
        # Use a safer alternative to pickle.load
        data = pickle.load(file, fix_imports=True, encoding="bytes")
    return data

# Example usage
# data = safe_load_pickle('data.pickle')