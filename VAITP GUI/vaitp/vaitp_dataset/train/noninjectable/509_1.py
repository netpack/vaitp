import pickle

def load_pickle(data):
    # Directly unpickle the data without any restrictions
    return pickle.loads(data)

# Usage example
if __name__ == "__main__":
    # Example of loading a potentially unsafe pickle file
    with open("data.pkl", "rb") as f:
        data = f.read()
        obj = load_pickle(data)
        print("Loaded object:", obj)