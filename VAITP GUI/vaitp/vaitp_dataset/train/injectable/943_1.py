import yaml

# Safe loading of YAML data
def safe_load_yaml(yaml_string):
    return yaml.safe_load(yaml_string)

# Example usage
yaml_data = """
!!python/object/apply:os.system ['echo Hello, World!']
"""

# This will raise an error if the YAML data is unsafe
try:
    result = safe_load_yaml(yaml_data)
except Exception as e:
    print(f"Error: {e}")