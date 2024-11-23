import os
import zipfile
import importlib.util

# Assume this function is called to process uploaded ZIP files containing custom connectors
def process_uploaded_zip(zip_file_path):
    with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
        zip_file.extractall('/tmp/custom_connectors')

    # Load custom Python code from the extracted files
    for file_name in os.listdir('/tmp/custom_connectors'):
        if file_name.endswith('.py'):
            file_path = os.path.join('/tmp/custom_connectors', file_name)
            spec = importlib.util.spec_from_file_location("custom_connector", file_path)
            custom_connector = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(custom_connector)  # This executes arbitrary code

# Example of an API endpoint that allows uploading a ZIP file
def upload_connector(zip_file):
    # Assume proper authorization checks are done here
    process_uploaded_zip(zip_file)