# Fixed version of the d8s-yaml package without the vulnerable dependency

# Removed the import of the potentially malicious package
# Instead, use a safe alternative or implement the required functionality directly

import yaml  # Assuming we are still using the PyYAML package

def safe_load_yaml(file_path):
    with open(file_path, 'r') as file:
        # Use safe_load to avoid executing arbitrary code
        return yaml.safe_load(file)

# Example usage
if __name__ == "__main__":
    data = safe_load_yaml('example.yaml')
    print(data)