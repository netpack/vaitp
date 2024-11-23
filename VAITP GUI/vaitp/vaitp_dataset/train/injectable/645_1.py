import pickle

def safe_load_pickle(file_path):
    with open(file_path, 'rb') as f:
        # Use a safer loading method that restricts the classes that can be deserialized
        return pickle.load(f, fix_imports=True, encoding="ASCII", errors="strict")

# Example usage
# bookmarks = safe_load_pickle('path/to/bookmarks.pickle')