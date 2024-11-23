import zipfile
import os

def safe_extract(zip_file, extract_to):
    # Ensure the extraction path is safe
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)

    with zipfile.ZipFile(zip_file) as zf:
        for member in zf.namelist():
            # Prevent directory traversal attacks
            if os.path.commonpath([extract_to, os.path.join(extract_to, member)]) != extract_to:
                raise Exception("Attempted Path Traversal in Zip File")
        
        zf.extractall(path=extract_to)

# Usage
safe_extract('example.bscw', '/safe/extraction/path')