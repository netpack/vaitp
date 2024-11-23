import yaml

# Unsafe loading of YAML files that can lead to arbitrary code execution
def load_yaml_unsafe(file_path):
    with open(file_path, 'r') as file:
        data = yaml.load(file, Loader=yaml.FullLoader)  # Vulnerable to code execution
    return data

# Example usage
data = load_yaml_unsafe('example.yaml')
print(data)