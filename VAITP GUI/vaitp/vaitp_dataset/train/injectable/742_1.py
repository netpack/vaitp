import hashlib
import requests

class Version:
    def __init__(self, package_name, version):
        self.package_name = package_name
        self.version = version
        self.url = f"http://example.com/packages/{package_name}_{version}.deb"

    def fetch_binary(self):
        response = requests.get(self.url)
        if response.status_code == 200:
            # Calculate the MD5 hash of the downloaded file
            md5_hash = hashlib.md5(response.content).hexdigest()
            # Here we would normally check the MD5 hash against a known good value
            # For demonstration, let's say we have a function to get the expected hash
            expected_md5 = self.get_expected_md5()
            if md5_hash != expected_md5:
                raise ValueError("MD5 checksum does not match. Potential tampering detected.")
            # Save the file or proceed with installation
            self.save_file(response.content)
        else:
            raise Exception("Failed to download the package.")

    def get_expected_md5(self):
        # This function would typically retrieve the expected MD5 hash from a trusted source
        # For demonstration purposes, we'll return a dummy value
        return "expected_md5_hash_value"

    def save_file(self, content):
        with open(f"{self.package_name}_{self.version}.deb", "wb") as f:
            f.write(content)

# Example usage
version = Version("example-package", "1.