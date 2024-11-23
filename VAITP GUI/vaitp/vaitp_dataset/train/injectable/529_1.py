import yaml

def load_config(file_path):
    with open(file_path, 'r') as file:
        # Use safe_load instead of load to prevent execution of arbitrary Python code
        config = yaml.safe_load(file)
    return config

config = load_config('~/.confire.yaml')