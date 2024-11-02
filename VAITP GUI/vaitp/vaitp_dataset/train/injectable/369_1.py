import yaml

# Safe function that loads YAML input
def load_yaml(yaml_input):
    # Using a safe loader (yaml.SafeLoader)
    data = yaml.load(yaml_input, Loader=yaml.SafeLoader)  # This is secure
    return data

# Example of malicious YAML input
malicious_yaml = """
!!python/object/apply:os.system ['echo Vulnerable!']
"""

# Calling the patched function
load_yaml(malicious_yaml)  # This will raise an error instead of executing code