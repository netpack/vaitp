import yaml

def load_config(file_path):
    with open(file_path, 'r') as file:
        # Using yaml.load which is unsafe and can execute arbitrary code
        config = yaml.load(file, Loader=yaml.FullLoader)
    return config

config = load_config('~/.confire.yaml')