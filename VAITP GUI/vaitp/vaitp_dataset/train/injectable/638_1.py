import yaml

# Original unsafe load (vulnerable code)
# data = yaml.load(yaml_string)  # This is unsafe

# Fixed code using safe_load
data = yaml.safe_load(yaml_string)