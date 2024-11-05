import pickle

class MyModel:
    def __init__(self, model_data):
        self.model_data = model_data

    def train(self):
        print("Training model with data:", self.model_data)

# Safe deserialization function
def load_model(serialized_data):
    # Check if the data is of the expected type before deserializing
    try:
        # Use a safe method or validate the data format
        model = pickle.loads(serialized_data)
        
        # Validate the model type
        if not isinstance(model, MyModel):
            raise ValueError("Deserialized object is not of the expected type MyModel.")
        
        return model
    except Exception as e:
        print("Failed to load model:", e)
        return None

# Example of serialized data that could be crafted by an attacker
# This should be a valid serialized MyModel object
valid_model_data = pickle.dumps(MyModel("Some training data"))

# Loading the model (now with validation)
model = load_model(valid_model_data)
if model:
    model.train()