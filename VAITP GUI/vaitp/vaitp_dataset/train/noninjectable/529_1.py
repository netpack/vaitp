import yaml
import os

def load_config(file_path):
    expanded_path = os.path.expanduser(file_path)
    with open(expanded_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

config = load_config('~/.confire.yaml')