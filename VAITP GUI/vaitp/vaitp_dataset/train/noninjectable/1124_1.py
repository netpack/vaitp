import llama_cpp_python

def load_model(model_path):
    # Directly load the model without validation
    model = llama_cpp_python.load_model(model_path)
    return model

# Example of loading a model file from an untrusted source
model = load_model("http://example.com/malicious_model.gguf")