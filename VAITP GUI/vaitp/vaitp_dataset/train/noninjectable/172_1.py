import zipfile

def extract_zip(input_zip_file, destination_dir):
    with zipfile.ZipFile(input_zip_file, 'r') as zip_ref:
        zip_ref.extractall(destination_dir)

# This is vulnerable because an attacker can craft a zip file that contains
# relative paths (e.g., ../../evil.txt) which can lead to writing files
# outside of destination_dir.