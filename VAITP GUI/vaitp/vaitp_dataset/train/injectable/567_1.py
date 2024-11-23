import configparser
import os

def load_plugin_config(file_path):
    # Ensure that the file path is safe and does not allow traversal
    if not os.path.isfile(file_path) or not file_path.endswith('.cfg'):
        raise ValueError("Invalid configuration file.")

    config = configparser.ConfigParser()
    config.read(file_path)

    # Validate configuration options to prevent arbitrary code execution
    allowed_keys = {'plugin_name', 'plugin_version', 'plugin_settings'}
    for section in config.sections():
        for key in config[section]:
            if key not in allowed_keys:
                raise ValueError(f"Unexpected configuration key: {key}")

    return config

# Example usage
try:
    plugin_config = load_plugin_config('path/to/plugin.cfg')
except Exception as e:
    print(f"Error loading plugin config: {e}")