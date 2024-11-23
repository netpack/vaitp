import skops

# Example of safe loading of a model using skops
# Ensure to use a trusted source for the model file
def load_model(file_path):
    with open(file_path, 'rb') as f:
        model = skops.load(f)
    return model

# Usage
# model = load_model('trusted_model.skops')