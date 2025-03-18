import yaml

def load_yaml(data):
    try:
        return yaml.load(data, Loader=yaml.Loader)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")

yaml_data = """
!!python/object/apply:os.system
args: ['ls -l']
"""
load_yaml(yaml_data)