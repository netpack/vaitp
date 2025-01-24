
import os
import tarfile
import zipfile
from urllib.request import urlretrieve

def safe_get_file(url, cache_dir='.', extract=False):
    """Download a file and optionally extract it safely."""
    # Check for valid cache directory
    if not os.path.isdir(cache_dir) or not os.access(cache_dir, os.W_OK):
        raise PermissionError("Invalid cache directory.")
    
    filename = os.path.join(cache_dir, os.path.basename(url))

    # Download the file
    urlretrieve(url, filename)

    if extract:
        # Ensure we are extracting to a safe directory
        safe_extract(filename, cache_dir)

    return filename

def safe_extract(file_path, extract_to='.'):
    """Extract a tar or zip file safely."""
    # Check for valid file path
    if not os.path.isfile(file_path):
        raise FileNotFoundError("Invalid file path.")
    
    # Check for valid extract directory
    if not os.path.isdir(extract_to):
        raise NotADirectoryError("Extract directory does not exist.")
    
    if file_path.endswith('.tar.gz') or file_path.endswith('.tgz'):
        with tarfile.open(file_path, 'r:gz') as tar:
            # Extract files to a specific directory only
            tar.extractall(path=extract_to)
    elif file_path.endswith('.zip'):
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            # Extract files to a specific directory only
            zip_ref.extractall(path=extract_to)

# Usage example
# safe_get_file('http://example.com/somefile.tar.gz', extract=True)