import tarfile
import re

# Example of a vulnerable tarfile extraction
def vulnerable_tarfile_extract(tar_path, extract_path):
    with tarfile.open(tar_path, 'r') as tar:
        for member in tar.getmembers():
            # Vulnerable regex pattern that can cause excessive backtracking
            if re.match(r'^(.*?)(\.\.?)', member.name):
                tar.extract(member, path=extract_path)

# Usage
# vulnerable_tarfile_extract('example_vulnerable.tar', './extracted')