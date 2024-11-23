import yaml

# Use safe_load instead of full_load to avoid arbitrary code execution
with open('untrusted_input.yaml', 'r') as file:
    data = yaml.safe_load(file)

# Process the data safely
print(data)