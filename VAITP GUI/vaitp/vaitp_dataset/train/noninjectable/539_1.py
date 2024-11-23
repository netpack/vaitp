import yaml

def load_yaml(data):
    return yaml.load(data)

def load_yamlf(filename):
    with open(filename, 'r') as f:
        return yaml.load(f)