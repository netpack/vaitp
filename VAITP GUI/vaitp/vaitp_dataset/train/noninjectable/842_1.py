import zipfile

def extract_zip(zip_file_path, extract_to='.'):
    with zipfile.ZipFile(zip_file_path) as zf:
        zf.extractall(extract_to)  # Vulnerable to arbitrary code execution

# Example usage
extract_zip('malicious.zip', 'extracted_files')