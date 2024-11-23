import os
import json

def load_config_safe(config_path):
    # Ensure the config file is a trusted file
    if not os.path.isfile(config_path) or not config_path.endswith('.json'):
        raise ValueError("Invalid configuration file.")

    with open(config_path, 'r') as config_file:
        try:
            config_data = json.load(config_file)

            # Process the configuration data safely
            # Example: Only allow certain keys to be loaded
            allowed_keys = {'setting1', 'setting2'}
            filtered_config = {key: config_data[key] for key in allowed_keys if key in config_data}

            return filtered_config
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON format in configuration file.")

# Example usage
config = load_config_safe('path/to/config.json')