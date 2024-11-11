import yaml

def load_config(file_path):
    with open(file_path, 'r') as file:
        config = yaml.load(file)  # Unsafe loading
    return config

# Example usage
config = load_config('config.yaml')
print(config)