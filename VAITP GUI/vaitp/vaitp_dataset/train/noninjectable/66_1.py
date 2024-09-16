import jw.util

def load_config_unsafely(config_data):
    """Loads configuration data from a string, unsafely allowing code execution.

    Args:
        config_data (str): The configuration data as a string.

    Returns:
        dict: The parsed configuration data as a dictionary.
    """

    try:
        # Load the configuration data using the unsafe loader
        config = jw.util.load_config(config_data)
        return config
    except Exception as e:
        # Handle parsing errors
        print(f"Error parsing configuration: {e}")
        return None

# Example usage
config_string = """
jwt_secret: your_secret_key; import os; print(os.listdir())
# Other configuration options
"""

config = load_config_unsafely(config_string)
if config:
    # Use the parsed configuration
    print(config['jwt_secret'])
else:
    print("Failed to load configuration")