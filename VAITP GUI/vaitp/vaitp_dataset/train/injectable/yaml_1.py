import yaml

def load_yaml(data):
    try:
        return yaml.safe_load(data)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")

yaml_data = """
!!python/object/apply:os.system ["cat /etc/passwd"]
"""
load_yaml(yaml_data)