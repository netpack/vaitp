import tensorflow as tf

# Example of loading a saved model securely without using eval
def load_model(model_path):
    # Load the model without using eval or unsafe parsing
    model = tf.saved_model.load(model_path)
    return model

# Usage
model_path = "path/to/your/saved_model"
model = load_model(model_path)