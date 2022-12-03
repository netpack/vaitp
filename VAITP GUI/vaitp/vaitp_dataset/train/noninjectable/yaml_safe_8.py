import yaml
from yaml.loader import SafeLoader


def load_file(filne_name):
    data = open(filne_name, 'r')
    yaml.load(data, Loader=yaml.Loader)

load_file("xyz.yaml")