import hashlib
import requests

class Version:
    def __init__(self, url, expected_sha256=None):
        self.url = url
        self.expected_sha256 = expected_sha256

    def fetch_binary(self):
        """Fetches a binary from the given URL, verifying the SHA256 hash."""
        response = requests.get(self.url, stream=True)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        hasher = hashlib.sha256()
        for chunk in response.iter_content(chunk_size=4096):
            hasher.update(chunk)
        actual_sha256 = hasher.hexdigest()

        if self.expected_sha256:
            if actual_sha256 != self.expected_sha256:
                raise ValueError(f"SHA256 mismatch: Expected {self.expected_sha256}, got {actual_sha256}")

        # Simulate writing the binary to a file or using it
        return response.content



class Package:
    def __init__(self, binary_url, binary_sha256):
        self.binary_version = Version(binary_url, binary_sha256)
    
    def install(self):
      binary_data = self.binary_version.fetch_binary()
      # Simulate the installation process 
      print("Binary installed")


def _fetch_archives(package_list):
    """Fetches archives from a list of packages."""
    for package in package_list:
        package.install()


if __name__ == '__main__':
    # Example of a legitimate package with a valid SHA256
    valid_package = Package(
       "https://example.com/my_package.bin", # URL of a package
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" # SHA256 hash of that package
    )
    
    # Example of a package with a missing hash, which should be blocked by the fix.
    package_no_hash = Package(
        "https://example.com/malicious_package.bin", # Malicious package url
        None  # Simulate package without expected hash.
    )

    try:
        _fetch_archives([valid_package])  # This should work.
    except ValueError as e:
        print(f"Error installing package 1: {e}")
    
    try:
        _fetch_archives([package_no_hash]) # This should raise an error due to no verification
    except ValueError as e:
      print(f"Error installing package 2: {e}")