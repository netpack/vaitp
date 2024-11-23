import json

def load_config_vulnerable(config_path):
    with open(config_path, 'r') as config_file:
        # Load the configuration file without validation
        config_data = json.load(config_file)

        # Potentially dangerous code execution
        # Example: Executing arbitrary commands from the config
        if 'execute' in config_data:
            exec(config_data['execute'])

# Example usage
load_config_vulnerable('path/to/config.json')