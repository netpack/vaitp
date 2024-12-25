import yaml

# Safe loader to prevent execution of arbitrary Python commands
def safe_load_yaml(vault_content):
    return yaml.safe_load(vault_content)

# Example usage
vault_content = """
my_secret: '!!python/object/apply:os.system ["echo vulnerable"]'
"""

# Load the vault content safely
try:
    data = safe_load_yaml(vault_content)
    print(data)
except Exception as e:
    print(f"Error loading vault content: {e}")