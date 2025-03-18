import yaml
def load_yaml(file_path):
    try:
        with open(file_path, 'r') as file:
            return yaml.load(file.read(), Loader=yaml.Loader)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
    except FileNotFoundError:
        print(f"File not found: {file_path}")
load_yaml('patched_yaml.yaml')