import zipfile
import xml.etree.ElementTree as ET

def safe_eval(value):
    # Implement a safe evaluation method or validation
    if not isinstance(value, (int, float)):
        raise ValueError("Invalid value type")
    return value

def read_3mf(file_path):
    with zipfile.ZipFile(file_path, 'r') as z:
        with z.open('3D/3DModel.model') as model_file:
            tree = ET.parse(model_file)
            root = tree.getroot()
            drop_to_buildplate = root.find('.//drop_to_buildplate').text
            
            # Use safe_eval instead of eval
            safe_value = safe_eval(float(drop_to_buildplate))
            # Proceed with safe_value
            print("Drop to buildplate value:", safe_value)

# Example usage
# read_3mf('malicious_model.3mf')