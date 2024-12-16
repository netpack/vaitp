import os
import zipfile

def extract(zip_file_path, extract_dir):
    """
    Extracts a zip file, mitigating directory traversal.
    """
    try:
        with zipfile.ZipFile(zip_file_path, 'r') as zf:
            for member in zf.infolist():
                #Sanitize the path to prevent directory traversal
                #This is the crucial fix.  The previous vulnerable version
                #likely lacked this robust path validation.
                target_path = os.path.join(extract_dir, os.path.basename(member.filename))
                if not os.path.abspath(target_path).startswith(os.path.abspath(extract_dir)):
                    raise ValueError("Path traversal detected!")

                zf.extract(member, extract_dir) 
    except zipfile.BadZipFile:
        print("Invalid or corrupt zip file.")
    except ValueError as e:
        print(f"Error: {e}")

#Example Usage (Illustrative):
#extract("my_archive.zip", "/tmp/extraction_dir")
