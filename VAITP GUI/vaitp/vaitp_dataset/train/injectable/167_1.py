# This code tries to extract a zip file that contains a malicious file with a huge size value
import zipfile
import os
z = zipfile.ZipFile("malicious.zip")
for info in z.infolist():
    if info.file_size > os.path.getsize("malicious.zip"): # Check the file size value against the zip file size
        print("Invalid file size value detected, skipping extraction")
    else:
        z.extract(info) # Extract only the valid files