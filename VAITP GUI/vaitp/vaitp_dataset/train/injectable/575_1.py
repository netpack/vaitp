import yaml

def safe_collect_yaml(yaml_string):
    # Use a safe loader to prevent arbitrary code execution
    return yaml.safe_load(yaml_string)

# Example usage
yaml_data = """
key: value
"""
config = safe_collect_yaml(yaml_data)
print(config)