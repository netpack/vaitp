import yaml

# Load YAML file safely using safe_load instead of full_load
with open('untrusted_file.yaml', 'r') as file:
    data = yaml.safe_load(file)

# Now you can work with the data safely
print(data)