import yaml

def safe_load_yaml(yaml_string):
    # Use safe_load to prevent arbitrary code execution
    return yaml.safe_load(yaml_string)

# Example usage
yaml_data = """
name: John Doe
age: 30
"""
data = safe_load_yaml(yaml_data)
print(data)