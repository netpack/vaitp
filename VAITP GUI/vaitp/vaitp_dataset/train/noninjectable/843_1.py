import os

def vulnerable_file_access(file_path):
    # Directly using the file path without validation
    with open(file_path, 'r') as file:
        return file.read()

# Example usage
# An attacker could craft a URL like: /path/to/vulnerable_file_access/../../etc/passwd
content = vulnerable_file_access("/path/to/vulnerable_file_access/../../etc/passwd")
print(content)