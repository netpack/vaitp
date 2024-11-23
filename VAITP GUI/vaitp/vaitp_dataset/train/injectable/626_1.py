import yaml

# Safe loading of YAML data
def safe_load_yaml(yaml_data):
    return yaml.safe_load(yaml_data)

# Example usage
yaml_data = """
- !!python/object/apply:os.system
  args: ["echo vulnerable"]
"""

# This will raise an exception or return None instead of executing arbitrary code
try:
    result = safe_load_yaml(yaml_data)
    print(result)
except Exception as e:
    print("Error:", e)