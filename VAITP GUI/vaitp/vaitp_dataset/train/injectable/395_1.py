import yaml

# Secured code that loads a YAML file
def load_model_config(file_path):
    with open(file_path, 'r') as file:
        config = yaml.safe_load(file)  # Safe loading of YAML
    return config

# Example usage
config = load_model_config('model_config.yaml')
print(config)