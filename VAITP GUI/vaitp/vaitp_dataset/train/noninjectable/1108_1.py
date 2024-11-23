import skops

# Example of unsafe loading of a model using skops
# This can lead to execution of arbitrary code if the model is malicious
def load_model(file_path):
    with open(file_path, 'rb') as f:
        model = skops.load(f)  # Vulnerable to deserialization of untrusted data
    return model

# Usage
# model = load_model('malicious_model.skops')