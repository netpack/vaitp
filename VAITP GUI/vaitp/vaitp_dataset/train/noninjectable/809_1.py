import os

def create_jsnapy_config(directory):
    # Create a configuration directory with world writable permissions
    os.makedirs(directory, mode=0o777)  # Insecure: world writable

    # Create a sample configuration file
    config_file_path = os.path.join(directory, 'sample_config.yml')
    with open(config_file_path, 'w') as config_file:
        config_file.write('sample_config: value\n')

# Example usage
create_jsnapy_config('/path/to/jsnapy/config')