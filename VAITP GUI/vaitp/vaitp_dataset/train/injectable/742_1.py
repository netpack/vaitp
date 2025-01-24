import hashlib
import requests
import os
from urllib.parse import urlparse

class Version:
    def __init__(self, package_name, version):
        self.package_name = package_name
        self.version = version
        self.url = f"https://example.com/packages/{package_name}_{version}.deb"

    def fetch_binary(self):
        try:
            response = requests.get(self.url, stream=True, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to download the package: {e}")

        hasher = hashlib.sha256()
        for chunk in response.iter_content(chunk_size=4096):
            hasher.update(chunk)
        sha256_hash = hasher.hexdigest()

        expected_sha256 = self.get_expected_sha256()
        if sha256_hash != expected_sha256:
            raise ValueError("SHA256 checksum does not match. Potential tampering detected.")

        self.save_file(response.content)


    def get_expected_sha256(self):
        # This function would typically retrieve the expected SHA256 hash from a trusted source
        # For demonstration purposes, we'll return a dummy value
        return "expected_sha256_hash_value"

    def save_file(self, content):
        filename = os.path.basename(urlparse(self.url).path)
        if not filename:
            filename = f"{self.package_name}_{self.version}.deb"
        
        if '..' in filename or filename.startswith('/'):
            raise ValueError("Invalid filename, potential path traversal.")
        
        filepath = os.path.join(os.getcwd(), filename)
        
        try:
            with open(filepath, "wb") as f:
                f.write(content)
        except IOError as e:
            raise Exception(f"Failed to save file: {e}")
