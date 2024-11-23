import yaml

def collect_yaml(yaml_string):
    # This method uses the unsafe loader, which can execute arbitrary code
    return yaml.load(yaml_string, Loader=yaml.FullLoader)

# Example usage
yaml_data = """
key: !!python/object/apply:os.system ['echo vulnerable']
"""
config = collect_yaml(yaml_data)
print(config)