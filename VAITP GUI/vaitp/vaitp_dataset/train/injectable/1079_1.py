import zipfile
import io
import os

# Create a zip file that demonstrates the vulnerability
with zipfile.ZipFile('vulnerable.zip', 'w') as zf:
    # Create a zip bomb with overlapping entries
    zf.writestr('file1.txt', b'A' * (10**6))  # 1 MB file
    zf.writestr('file2.txt', b'B' * (10**6))  # 1 MB file
    # Overlapping entry
    zf.writestr('file1.txt', b'A' * (10**6))  # Overlapping entry

# Attempt to read the vulnerable zip file (this will now raise an exception)
try:
    with zipfile.ZipFile('vulnerable.zip', 'r') as zf:
        print(zf.namelist())
        
        
        for member in zf.infolist():
            
            if member.file_size > 10 * 1024 * 1024:  # limit to 10MB
                raise Exception("File size exceeds limit")
            
            if member.filename.startswith('/'):
                raise Exception("Absolute path not allowed")
                
            if ".." in member.filename:
                  raise Exception("Relative path not allowed")
            
        zf.extractall('extracted_files')
except Exception as e:
    print(f"Error: {e}")
    
try:
    os.remove('vulnerable.zip')
except:
    pass

try:
    os.rmdir('extracted_files')
except:
    pass
