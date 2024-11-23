import yaml

# Using full_load which is vulnerable to arbitrary code execution
with open('untrusted_input.yaml', 'r') as file:
    data = yaml.full_load(file)

# Process the data, which could potentially execute arbitrary code
print(data)