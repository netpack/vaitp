import pickle

def renderLocalView(data):
    # Vulnerable code using pickle to deserialize data unsafely
    try:
        # 'data' is expected to be a pickled object
        deserialized_data = pickle.loads(data)
        # Process the deserialized data
        return process_data(deserialized_data)
    except Exception as e:
        raise ValueError("Error processing data: {}".format(e))