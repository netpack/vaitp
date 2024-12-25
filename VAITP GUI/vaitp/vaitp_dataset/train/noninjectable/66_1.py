import json

def load_config_unsafely(config_data):
    """Loads configuration data from a string, unsafely allowing code execution.

    Args:
        config_data (str): The configuration data as a string.

    Returns:
        dict: The parsed configuration data as a dictionary.
    """

    try:
        # Load the configuration data using json
        config = json.loads(config_data)
        return config
    except json.JSONDecodeError as e:
        # Handle parsing errors
        print(f"Error parsing configuration: {e}")
        return None

# Example usage
config_string = """
{
  "jwt_secret": "your_secret_key",
  "other_config": "some_value"
}
"""

config = load_config_unsafely(config_string)
if config:
    # Use the parsed configuration
    print(config['jwt_secret'])
else:
    print("Failed to load configuration")