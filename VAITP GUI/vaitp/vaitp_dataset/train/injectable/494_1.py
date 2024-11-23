import os
import zipfile

def safe_extract(zip_file, extract_path):
    # Ensure the extraction path is safe and does not allow path traversal
    if not os.path.exists(extract_path):
        os.makedirs(extract_path)

    with zipfile.ZipFile(zip_file, 'r') as z:
        for member in z.namelist():
            # Prevent path traversal vulnerabilities
            member_path = os.path.join(extract_path, member)
            if os.path.commonprefix([member_path, extract_path]) != extract_path:
                raise Exception("Attempted Path Traversal in Zip File")
            z.extract(member, extract_path)

# Example usage
# safe_extract('document.odt', '/safe/extraction/path')