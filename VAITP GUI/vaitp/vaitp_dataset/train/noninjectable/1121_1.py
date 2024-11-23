import onnx

def load_model(model_path):
    # Directly load the model without any path validation
    model = onnx.load(model_path)
    return model

# Example usage
model = load_model("../../etc/passwd")  # This represents a potential directory traversal