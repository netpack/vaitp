import os
import zipfile

def extract_zip_safe(input_zip_file, destination_dir):
    with zipfile.ZipFile(input_zip_file, 'r') as zip_ref:
        for member in zip_ref.infolist():
            # Resolve the absolute path of the intended destination
            extracted_path = os.path.abspath(os.path.join(destination_dir, member.filename))
            
            # Ensure the path starts with the expected destination directory
            if not extracted_path.startswith(os.path.abspath(destination_dir)):
                raise Exception("Found a file in the zip archive that extracts outside the destination directory.")
            
            # Extract the file after validation
            zip_ref.extract(member, destination_dir)

# This patched version checks that the extracted files do not end up outside
# of the destination_dir by validating their resolved absolute paths.