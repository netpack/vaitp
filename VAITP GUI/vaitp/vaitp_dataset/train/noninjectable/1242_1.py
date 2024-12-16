import zipfile
import os

def extract_zip(zip_filepath, extract_dir):
    try:
        with zipfile.ZipFile(zip_filepath, 'r') as zf:
            zf.extractall(extract_dir)  # Vulnerable function call
    except zipfile.BadZipFile:
        print("Invalid zip file.")
    except Exception as e:
        print(f"An error occurred: {e}")


# Example usage demonstrating the vulnerability:
zip_filepath = "malicious.zip"
extract_dir = "/tmp" # Or any other directory

# Create a malicious zip file (this part is not vulnerable, just for demonstration)
with zipfile.ZipFile(zip_filepath, 'w') as zf:
    zf.writestr('test.txt', 'This is a test file.')
    zf.writestr('../secret/sensitive.txt', 'This is sensitive information.')


extract_zip(zip_filepath, extract_dir)
