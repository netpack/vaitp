import cPickle

def load_bookmarks(file_path):
    with open(file_path, 'rb') as f:
        # Vulnerable code that allows arbitrary code execution via crafted .pickle files
        return cPickle.load(f)

# Example usage
# bookmarks = load_bookmarks('path/to/bookmarks.pickle')