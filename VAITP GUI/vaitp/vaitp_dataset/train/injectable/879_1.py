import yaml

# Safe loading function that avoids arbitrary code execution
def safe_load_yaml(yaml_string):
    return yaml.safe_load(yaml_string)

# Example of deserializing a Keras model in a safe manner
yaml_model = """
!<tag:keras.io:layer>
class_name: Dense
config:
  units: 32
  activation: relu
"""

# Load the YAML safely
model_config = safe_load_yaml(yaml_model)
print(model_config)