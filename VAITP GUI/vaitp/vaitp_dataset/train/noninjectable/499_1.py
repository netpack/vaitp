import yaml

def read_yaml_file(file_path):
    with open(file_path, 'r') as file:
        # Using load instead of safe_load, which can execute arbitrary code
        return yaml.load(file, Loader=yaml.FullLoader)