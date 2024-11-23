import onnx
import os

def load_model_safe(model_path):
    # Ensure the model path is within a safe directory
    safe_directory = os.path.abspath("safe_directory")
    model_path = os.path.abspath(model_path)

    if not model_path.startswith(safe_directory):
        raise ValueError("Model path is outside of the safe directory.")

    model = onnx.load(model_path)
    return model

# Example usage
try:
    model = load_model_safe("path/to/your/model.onnx")
except ValueError as e:
    print(e)