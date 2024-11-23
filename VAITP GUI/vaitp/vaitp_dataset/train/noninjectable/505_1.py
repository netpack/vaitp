import usd

def load_usd(file_path):
    # Load the USD file and execute any embedded Python code
    stage = usd.Stage.Open(file_path)
    
    # Execute embedded Python code in the USD file
    for layer in stage.GetRootLayer().GetSubLayers():
        exec(layer.GetSourceUri())
    
    return stage

# Example usage
try:
    stage = load_usd("path/to/malicious.usd")
except Exception as e:
    print(f"Error loading USD file: {e}")