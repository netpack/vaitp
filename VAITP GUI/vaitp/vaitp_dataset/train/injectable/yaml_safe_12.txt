import yaml

def load_file(filne_name):
    data = open(filne_name, 'r')
    yaml.safe_load(data)

load_file("xyz.yaml")