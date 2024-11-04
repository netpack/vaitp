import yaml

# Vulnerable code that loads a YAML file
def load_model_config(file_path):
    with open(file_path, 'r') as file:
        config = yaml.load(file)  # Vulnerable to arbitrary code execution
    return config

# Example usage
config = load_model_config('model_config.yaml')
print(config)