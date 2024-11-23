import pickle

# Vulnerable code example using unpickle
def load_data(data):
    # This method uses pickle.loads, which can execute arbitrary code
    return pickle.loads(data)

# Example of potentially malicious serialized data
malicious_data = pickle.dumps({'__class__': 'os.system', '__args__': ('echo Vulnerable!',)})

# Load the data (this would execute the command if the data is malicious)
result = load_data(malicious_data)