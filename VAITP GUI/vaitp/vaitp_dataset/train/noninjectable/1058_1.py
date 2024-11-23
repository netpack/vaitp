import zipfile
from pathlib import Path

# Example of how the vulnerability could be exploited
def vulnerable_zip_path_handling(zip_file_path):
    with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
        zip_path = zipfile.Path(zip_file)
        # This could lead to an infinite loop with a malicious zip file
        for name in zip_path.namelist():  # Vulnerable to infinite loop
            print(name)

# Call the function with a path to a potentially malicious zip file
vulnerable_zip_path_handling('malicious.zip')