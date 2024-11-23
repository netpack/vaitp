import usd

def safe_load_usd(file_path):
    # Load the USD file without executing embedded Python code
    stage = usd.Stage.Open(file_path)
    
    # Disable execution of embedded scripts
    for layer in stage.GetRootLayer().GetSubLayers():
        layer.SetPermission(usd.Layer.Permission.READ_ONLY)
    
    return stage

# Example usage
try:
    safe_stage = safe_load_usd("path/to/malicious.usd")
except Exception as e:
    print(f"Failed to load USD file safely: {e}")