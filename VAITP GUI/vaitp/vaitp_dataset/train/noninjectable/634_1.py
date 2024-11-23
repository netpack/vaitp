import pickle

def load_metadata(xattrs):
    metadata = {}
    for key, value in xattrs.items():
        if key.startswith('user.'):
            # Using pickle to load metadata, which is unsafe
            try:
                metadata[key] = pickle.loads(value)
            except (pickle.UnpicklingError, EOFError, AttributeError):
                # Handle errors during unpickling
                continue
    return metadata

# Example usage
xattrs = {
    'user.metadata': b'cos\nsystem\nexec\n(S\'echo vulnerable\'\n.'
}

metadata = load_metadata(xattrs)
print(metadata)