import yaml

# This example demonstrates the vulnerability by using full_load
with open('untrusted_file.yaml', 'r') as file:
    data = yaml.full_load(file)

# The following line could potentially execute arbitrary code
print(data)