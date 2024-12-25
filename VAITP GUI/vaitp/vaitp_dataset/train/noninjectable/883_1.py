import os
import zipfile
import importlib.util
import shutil

# Assume this function is called to process uploaded ZIP files containing custom connectors
def process_uploaded_zip(zip_file_path):
    extract_path = '/tmp/custom_connectors'
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
            zip_file.extractall(extract_path)

        # Load custom Python code from the extracted files
        for file_name in os.listdir(extract_path):
            if file_name.endswith('.py'):
                file_path = os.path.join(extract_path, file_name)
                spec = importlib.util.spec_from_file_location(f"custom_connector_{file_name}", file_path)
                if spec is None:
                  print(f"Could not load spec from file {file_path}")
                  continue
                custom_connector = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(custom_connector)  # This executes arbitrary code
    except Exception as e:
        print(f"Error processing zip file: {e}")
    finally:
      # Clean up the extracted directory
      if os.path.exists(extract_path):
        shutil.rmtree(extract_path)

# Example of an API endpoint that allows uploading a ZIP file
def upload_connector(zip_file):
    # Assume proper authorization checks are done here
    process_uploaded_zip(zip_file)