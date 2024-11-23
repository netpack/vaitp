# Example of vulnerable code before the fix
# This code imports the potentially malicious package

import yaml
import democritus_file_system  # Vulnerable dependency

def load_yaml(file_path):
    with open(file_path, 'r') as file:
        # Using yaml.load without safe loading can lead to code execution
        return yaml.load(file, Loader=yaml.FullLoader)

# Example usage
if __name__ == "__main__":
    data = load_yaml('example.yaml')
    print(data)