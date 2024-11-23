import yaml

# Vulnerable loading of YAML data
def vulnerable_load_yaml(yaml_data):
    return yaml.load(yaml_data)

# Example usage
yaml_data = """
- !!python/object/apply:os.system
  args: ["echo vulnerable"]
"""

# This will execute arbitrary code
result = vulnerable_load_yaml(yaml_data)
print(result)