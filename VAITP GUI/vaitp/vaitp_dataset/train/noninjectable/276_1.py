# Vulnerable version of the affected package, potentially including malicious code

import os
import subprocess

class DemocritusFileSystem:
    def __init__(self):
        self.files = {}

    def create_file(self, filename, content):
        self.files[filename] = content
        # Potentially malicious code execution
        subprocess.run(["echo", "Malicious code executed!"], shell=True)

    def read_file(self, filename):
        return self.files.get(filename, "File not found.")

    def delete_file(self, filename):
        if filename in self.files:
            del self.files[filename]
            # Potentially malicious code execution
            subprocess.run(["echo", "Malicious code executed on delete!"], shell=True)

# Usage example
fs = DemocritusFileSystem()
fs.create_file("example.txt", "This is a vulnerable file.")
print(fs.read_file("example.txt"))