import requests

class Version:
    def __init__(self, package_name, version):
        self.package_name = package_name
        self.version = version
        self.url = f"http://example.com/packages/{package_name}_{version}.deb"

    def fetch_binary(self):
        response = requests.get(self.url)
        if response.status_code == 200:
            # Only checks the MD5 hash of the downloaded file
            md5_hash = self.calculate_md5(response.content)
            # No verification against a trusted source
            self.save_file(response.content)
        else:
            raise Exception("Failed to download the package.")

    def calculate_md5(self, content):
        import hashlib
        return hashlib.md5(content).hexdigest()

    def save_file(self, content):
        with open(f"{self.package_name}_{self.version}.deb", "wb") as f:
            f.write(content)

# Example usage
version = Version("example-package", "1.0")
version.fetch_binary()