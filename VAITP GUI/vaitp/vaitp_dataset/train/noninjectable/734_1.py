import onnx

def load_onnx_model(model_path):
    # Load the ONNX model
    model = onnx.load(model_path)

    # Access external data paths without validation
    for tensor in model.graph.initializer:
        if tensor.external_data:
            external_data_path = tensor.external_data
            # Potentially unsafe: no checks on the external data path
            print(f"Loading external data from: {external_data_path}")

    return model

# Example usage
model = load_onnx_model("model.onnx")