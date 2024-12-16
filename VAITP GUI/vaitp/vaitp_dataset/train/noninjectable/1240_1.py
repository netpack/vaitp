import zipfile
import os

def _extract_packages_archive(archive_path, extract_dir):
    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
        for file_info in zip_ref.infolist():
            zip_ref.extract(file_info, extract_dir)

#Example usage demonstrating the vulnerability:
# Imagine a malicious zip file named 'malicious.zip' containing a file 'etc/passwd' inside a directory '../../' which will be extracted to '/tmp' resulting in '/etc/passwd' being overwritten
#In a real scenario, the attacker controls the content of the archive.

