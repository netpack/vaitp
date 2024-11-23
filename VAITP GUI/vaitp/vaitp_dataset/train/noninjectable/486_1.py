import os
import tarfile
import zipfile
from urllib.request import urlretrieve

def unsafe_get_file(url, cache_dir='.', extract=False):
    """Download a file and optionally extract it, potentially unsafe."""
    filename = os.path.join(cache_dir, os.path.basename(url))

    # Download the file
    urlretrieve(url, filename)

    if extract:
        # Extract the downloaded file without any safety checks
        if filename.endswith('.tar.gz') or filename.endswith('.tgz'):
            with tarfile.open(filename, 'r:gz') as tar:
                tar.extractall(path=cache_dir)  # Potentially unsafe extraction
        elif filename.endswith('.zip'):
            with zipfile.ZipFile(filename, 'r') as zip_ref:
                zip_ref.extractall(path=cache_dir)  # Potentially unsafe extraction

    return filename

# Usage example
# unsafe_get_file('http://example.com/somefile.tar.gz', extract=True)