import yaml

# Unsafe loading of YAML data
def unsafe_load_yaml(yaml_string):
    return yaml.load(yaml_string, Loader=yaml.Loader)

# Example usage
yaml_data = """
!!python/object/apply:os.system ['echo Hello, World!']
"""

# This could execute arbitrary code
result = unsafe_load_yaml(yaml_data)