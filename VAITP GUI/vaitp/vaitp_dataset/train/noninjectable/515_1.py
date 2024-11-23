import pickle

# Vulnerable unpickling function that allows arbitrary code execution
def vulnerable_load(data):
    return pickle.loads(data)

# Example usage
data = b'...'  # Pickled data that could execute arbitrary code
obj = vulnerable_load(data)