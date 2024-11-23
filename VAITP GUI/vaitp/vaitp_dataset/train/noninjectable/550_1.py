import yaml

def parse_yaml_query(yaml_query):
    # Vulnerable code: using load instead of safe_load
    return yaml.load(yaml_query)

# Example usage
yaml_query = """
- !!python/object/apply:os.system ['echo vulnerable code executed']
"""

# This will execute the command in the YAML due to the vulnerability
result = parse_yaml_query(yaml_query)
print(result)