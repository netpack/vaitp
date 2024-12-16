import zipfile
import os

# Function to safely process a zip file
def safe_process_zip(zip_path):
    with zipfile.ZipFile(zip_path) as z:
        for file_info in z.infolist():
            # Example of processing files safely
            print(f'Processing file: {file_info.filename}')

# Example usage
safe_process_zip('path/to/safe_zip_file.zip')