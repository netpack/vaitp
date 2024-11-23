import yaml

# Safe loading of YAML files to prevent arbitrary code execution
def load_yaml_safe(file_path):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
    return data

# Example usage
data = load_yaml_safe('example.yaml')
print(data)