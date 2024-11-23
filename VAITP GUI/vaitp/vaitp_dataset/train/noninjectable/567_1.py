import configparser

def load_plugin_config(file_path):
    config = configparser.ConfigParser()
    config.read(file_path)

    # Vulnerability: Arbitrary code execution via exec() on configuration values
    for section in config.sections():
        for key in config[section]:
            exec(config[section][key])  # This is insecure and allows arbitrary code execution

# Example usage
load_plugin_config('path/to/plugin.cfg')