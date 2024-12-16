import zipfile
from pathlib import Path

# Vulnerable function that may lead to an infinite loop
def vulnerable_process_zip(zip_path):
    with zipfile.ZipFile(zip_path) as z:
        for file_info in z.infolist():
            # Simulating a vulnerable operation that could lead to an infinite loop
            path = Path(file_info.filename)
            # Using joinpath in a way that could trigger the vulnerability
            new_path = Path('/some/base/path') / path
            while True:  # This represents the infinite loop
                pass  # Simulating the infinite loop condition

# Example usage with a crafted zip file
vulnerable_process_zip('path/to/vulnerable_zip_file.zip')