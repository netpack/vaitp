import tarfile
import os

def safe_extract(tar, path):
    # Get the absolute path of the extraction directory
    safe_path = os.path.abspath(path)
    
    for member in tar.getmembers():
        # Get the absolute path of the member
        member_path = os.path.abspath(os.path.join(safe_path, member.name))
        
        # Ensure the member path is within the safe extraction directory
        if not member_path.startswith(safe_path):
            raise Exception("Attempted Path Traversal Detected: {}".format(member.name))
    
    tar.extractall(path=safe_path)

def extract_package(package_path, extract_to):
    with tarfile.open(package_path, 'r:gz') as tar:
        safe_extract(tar, extract_to)

# Example usage
extract_package('malicious_package.tar.gz', '/safe/directory/')