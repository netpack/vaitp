import yaml

def safe_parse_yaml_query(yaml_query):
    # Use safe_load instead of load to prevent arbitrary code execution
    return yaml.safe_load(yaml_query)

# Example usage
yaml_query = """
- !!python/object/apply:os.system ['echo vulnerable code executed']
"""

# This will safely parse the YAML without executing the command
result = safe_parse_yaml_query(yaml_query)
print(result)