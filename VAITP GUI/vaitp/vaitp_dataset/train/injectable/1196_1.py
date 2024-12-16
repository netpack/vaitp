import tarfile
import re

# Example of a tarfile that does not allow excessive backtracking
def safe_tarfile_extract(tar_path, extract_path):
    with tarfile.open(tar_path, 'r') as tar:
        for member in tar.getmembers():
            # Use a safe regex pattern to validate member names
            if re.match(r'^[\w\-. ]+$', member.name):
                tar.extract(member, path=extract_path)
            else:
                raise ValueError("Unsafe tar member name detected")

# Usage
# safe_tarfile_extract('example.tar', './extracted')