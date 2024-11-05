import pickle

class MyModel:
    def __init__(self, model_data):
        self.model_data = model_data

    def train(self):
        print("Training model with data:", self.model_data)

# Simulating deserialization of untrusted data
def load_model(serialized_data):
    # Vulnerable deserialization
    model = pickle.loads(serialized_data)
    return model

# Example of serialized data that could be crafted by an attacker
malicious_data = b"cos\nsystem\n(S'echo Vulnerable code executed!'\n)"  # This would execute a system command

# Loading the model (vulnerable to code execution)
model = load_model(malicious_data)
model.train()