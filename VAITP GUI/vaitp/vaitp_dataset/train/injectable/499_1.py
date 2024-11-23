import yaml

def safe_read_yaml_file(file_path):
    with open(file_path, 'r') as file:
        # Use safe_load instead of load to prevent execution of arbitrary code
        return yaml.safe_load(file)