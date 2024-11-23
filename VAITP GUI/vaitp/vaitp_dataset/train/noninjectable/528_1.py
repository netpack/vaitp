import yaml

def load_yaml(yaml_string):
    # Using load instead of safe_load, which can execute arbitrary code
    return yaml.load(yaml_string)

# Example of potentially dangerous YAML input
yaml_data = """
!!python/object/apply:os.system ['echo Vulnerable']
"""
data = load_yaml(yaml_data)
print(data)