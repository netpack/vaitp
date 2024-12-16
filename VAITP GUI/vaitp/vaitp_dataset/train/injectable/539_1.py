import yaml

def load_yaml(data):
    return yaml.safe_load(data)

def load_yamlf(filename):
    with open(filename, 'r') as f:
        return yaml.safe_load(f)