import zipfile
from pathlib import Path

# Example of a safe way to handle zipfile.Path
def safe_zip_path_handling(zip_file_path):
    with zipfile.ZipFile(zip_file_path, 'r') as zip_file:
        zip_path = zipfile.Path(zip_file)
        try:
            for name in zip_path.namelist():  # This is safe in fixed versions
                print(name)
        except Exception as e:
            print(f"Error while processing zip file: {e}")

# Call the function with a path to a zip file
safe_zip_path_handling('example.zip')