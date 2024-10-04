# Import the zipfile module
import zipfile

# Define a limit for the maximum size of the extracted files
MAX_SIZE = 1000000 # 1 MB

# Open a ZIP file
with zipfile.ZipFile('file.zip', 'r') as zf:
    # Iterate over the files in the ZIP file
    for zinfo in zf.infolist():
        # Check if the file size exceeds the limit
        if zinfo.file_size > MAX_SIZE:
            # Raise an exception and abort the extraction
            raise zipfile.LargeZipFile(f"File {zinfo.filename} is too large")
        # Extract the file
        zf.extract(zinfo)