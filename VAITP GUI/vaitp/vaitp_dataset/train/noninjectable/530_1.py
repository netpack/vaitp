import pickle

# Vulnerable code that unpickles data from an untrusted source
def load_pickle(data):
    return pickle.loads(data)

# Example of potentially malicious pickled data
malicious_data = b"(C__main__\nMaliciousClass\nq\x00)\n."  # This would represent a crafted pickle

# This would execute arbitrary code when the malicious data is unpickled
loaded_data = load_pickle(malicious_data)