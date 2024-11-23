import yaml

# Vulnerable loading function that uses unsafe_load
def load_yaml_model(yaml_string):
    return yaml.unsafe_load(yaml_string)

# Example of deserializing a Keras model in a vulnerable manner
yaml_model = """
!<tag:keras.io:layer>
class_name: Dense
config:
  units: 32
  activation: relu
"""

# Load the YAML unsafely
model_config = load_yaml_model(yaml_model)
print(model_config)