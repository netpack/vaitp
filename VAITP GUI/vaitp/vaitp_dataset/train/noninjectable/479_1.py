import yaml

def load_config(file_path):
    with open(file_path, 'r') as file:
        config = yaml.safe_load(file)  # Safe loading
    return config

# Example usage
# Create a dummy config.yaml file for testing
with open('config.yaml', 'w') as f:
    f.write("name: test\nvalue: 123")
config = load_config('config.yaml')
print(config)