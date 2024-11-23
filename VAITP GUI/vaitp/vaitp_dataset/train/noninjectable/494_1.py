import zipfile

def extract_and_execute(zip_file):
    with zipfile.ZipFile(zip_file, 'r') as z:
        # Extract all files without any security checks
        z.extractall('/extraction/path')

        # Assume there is a Python script in the extracted files
        # This represents the potential execution of arbitrary code
        exec(open('/extraction/path/some_script.py').read())

# Example usage
# extract_and_execute('malicious_document.odt')