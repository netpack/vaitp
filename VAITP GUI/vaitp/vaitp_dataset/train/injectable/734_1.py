import os
import onnx

def safe_load_onnx_model(model_path, allowed_directory):
    # Normalize the allowed directory path
    allowed_directory = os.path.abspath(allowed_directory)

    # Load the ONNX model
    model = onnx.load(model_path)

    # Check external data paths
    for tensor in model.graph.initializer:
        if tensor.external_data:
            external_data_path = os.path.abspath(tensor.external_data)
            # Ensure the external data path is within the allowed directory
            if not external_data_path.startswith(allowed_directory):
                raise ValueError(f"External data path {external_data_path} is outside the allowed directory.")

    return model

# Example usage
try:
    model = safe_load_onnx_model("model.onnx", "/path/to/allowed/directory")
except ValueError as e:
    print(e)