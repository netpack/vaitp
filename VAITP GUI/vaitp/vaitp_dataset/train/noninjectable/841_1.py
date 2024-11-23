import tensorflow as tf

def load_model(model_path):
    # Load the SavedModel without validation
    model = tf.saved_model.load(model_path)
    
    # Directly convert to MLIR-based IR without checking the GraphDef
    mlir_ir = tf.experimental.mlir.convert_to_mlir(model)
    
    return mlir_ir

# Example usage
model_path = "path/to/saved_model"
mlir_ir = load_model(model_path)