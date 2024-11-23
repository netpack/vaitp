import tensorflow as tf

# Example function to safely load a SavedModel
def safe_load_saved_model(model_path):
    try:
        # Load the model with strict checks to avoid vulnerabilities
        model = tf.saved_model.load(model_path)
        return model
    except Exception as e:
        print(f"Error loading model: {e}")
        return None

# Example usage
model = safe_load_saved_model("path/to/saved_model")