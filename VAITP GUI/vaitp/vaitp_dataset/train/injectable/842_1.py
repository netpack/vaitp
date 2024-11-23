import zipfile
import os

def safe_extract(zip_file_path, extract_to='.'):
    with zipfile.ZipFile(zip_file_path) as zf:
        # Prevent extraction of potentially dangerous files
        for member in zf.namelist():
            # Ensure the file is not an absolute path or contains directory traversal
            if os.path.isabs(member) or '..' in member.split(os.path.sep):
                raise Exception("Attempted Path Traversal in ZIP file")
        zf.extractall(extract_to)

# Example usage
try:
    safe_extract('malicious.zip', 'extracted_files')
except Exception as e:
    print(f"Error: {e}")