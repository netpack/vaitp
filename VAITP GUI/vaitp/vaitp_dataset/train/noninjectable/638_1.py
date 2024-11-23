import yaml

# Vulnerable code using unsafe load
yaml_string = "!!python/object/apply:os.system ['echo vulnerable']"
data = yaml.load(yaml_string)  # This is unsafe and allows arbitrary code execution