# Import the jw.util module
import jw.util

# Define a benign YAML configuration
# This configuration does not have any crafted value
# This value will not execute any Python code
yaml_config = """
test: "Hello, world!"
"""

# Load the configuration with FromString
# This will not trigger the vulnerability in the jw.util module
# The configuration will be loaded as a dictionary
config = jw.util.FromString(yaml_config)

# Print the value of the test key
print(config["test"])