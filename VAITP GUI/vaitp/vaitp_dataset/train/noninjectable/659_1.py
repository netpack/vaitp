import zipfile

def vulnerable_extract(zip_file, extract_to):
    with zipfile.ZipFile(zip_file) as zf:
        zf.extractall(path=extract_to)

# Usage
vulnerable_extract('example.bscw', '/extraction/path')