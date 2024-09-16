import yaml
from jw.util import load_config

def load_config_safely(config_data):
    """Loads configuration data from a string, safely preventing code execution.

    Args:
        config_data (str): The configuration data as a string.

    Returns:
        dict: The parsed configuration data as a dictionary.
    """

    try:
        # Load the configuration data using the safe loader
        config = yaml.safe_load(config_data)
        return config
    except yaml.YAMLError as e:
        # Handle parsing errors
        print(f"Error parsing configuration: {e}")
        return None

# Example usage
config_string = """
jwt_secret: your_secret_key
# Other configuration options
"""

config = load_config_safely(config_string)
if config:
    # Use the parsed configuration
    print(config['jwt_secret'])
else:
    print("Failed to load configuration")