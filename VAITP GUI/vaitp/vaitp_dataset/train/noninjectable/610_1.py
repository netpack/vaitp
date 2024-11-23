import pickle
import os

def load_pickle(file_path):
    with open(file_path, 'rb') as file:
        # Vulnerable code that allows execution of arbitrary code
        data = pickle.load(file)
    return data

# Example usage
# data = load_pickle('data.pickle')