import tensorflow as tf

# Example code that demonstrates the vulnerability by loading a potentially malicious SavedModel
def load_saved_model(model_path):
    # Directly loading the SavedModel without validation
    model = tf.saved_model.load(model_path)
    return model

# Example usage
model = load_saved_model("path/to/malicious_saved_model")