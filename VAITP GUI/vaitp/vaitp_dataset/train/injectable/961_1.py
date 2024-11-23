from pydrive2.auth import GoogleAuth
import os
import yaml

# Load settings file securely to avoid YAML deserialization vulnerabilities
def load_settings_file_securely(file_path):
    with open(file_path, 'r') as file:
        # Load only trusted data, avoid executing arbitrary code
        data = yaml.safe_load(file)
    return data

# Ensure you are using a safe version of PyDrive2
gauth = GoogleAuth()

# Check for the presence of a malicious YAML file
current_directory = os.getcwd()
for file in os.listdir(current_directory):
    if file.endswith('.yaml') or file.endswith('.yml'):
        print(f"Warning: Found YAML file '{file}' in the current directory. Please ensure it is safe.")

# Load settings securely
settings = load_settings_file_securely('settings.yaml')
gauth.LoadSettings(settings)