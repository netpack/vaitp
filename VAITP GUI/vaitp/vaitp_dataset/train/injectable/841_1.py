import tensorflow as tf
import os

def safe_load_model(model_path):
    try:
        if not isinstance(model_path, str):
            raise ValueError("Model path must be a string.")
        if not os.path.exists(model_path):
              raise ValueError(f"Model path does not exist: {model_path}")
        if not os.path.isdir(model_path):
            raise ValueError(f"Model path is not a directory: {model_path}")
        
        # Load the SavedModel while ensuring that the model is valid
        model = tf.saved_model.load(model_path)
        
        # Validate the model's GraphDef before conversion to MLIR
        if not is_valid_graph_def(model):
            raise ValueError("Invalid GraphDef detected. The model may have been tampered with.")
        
        return model
    except Exception as e:
        print(f"Error loading model: {e}")
        return None

def is_valid_graph_def(model):
    try:
      # Check if the model has a signature
      if not model.signatures:
          return False

      # Example: Check for expected inputs/outputs in signature
      for signature_key in model.signatures:
        signature = model.signatures[signature_key]
        if not signature.inputs or not signature.outputs:
          return False

        #Example: Check input and output tensor specs
        for input_tensor in signature.inputs:
            if not isinstance(input_tensor, tf.TensorSpec):
                return False
        for output_tensor in signature.outputs:
            if not isinstance(output_tensor, tf.TensorSpec):
                return False

      # Example: Check for potentially dangerous ops
      dangerous_ops = ["Placeholder", "Identity", "Assert", "Print", "DebugIdentity"]  # Include ops based on your risk assessment
      for op in model.graph.get_operations():
          if op.type in dangerous_ops:
              return False
      return True
    except Exception:
        return False

# Example usage
model_path = "path/to/saved_model"
model = safe_load_model(model_path)
