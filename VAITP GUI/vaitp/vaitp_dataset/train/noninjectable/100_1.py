# Import the zipfile module
import zipfile

# Open a malicious ZIP file
with zipfile.ZipFile('zipbomb.zip', 'r') as zf:
    # Extract all the files in the ZIP file
    zf.extractall()