import requests
import hashlib

def download_package(package_name, version):
    url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    response = requests.get(url)
    response.raise_for_status()
    
    # Verify integrity using SHA256 hash
    package_info = response.json()
    package_url = package_info['urls'][0]['url']
    expected_hash = package_info['urls'][0]['digests']['sha256']
    
    package_response = requests.get(package_url)
    package_response.raise_for_status()
    
    # Calculate the hash of the downloaded package
    actual_hash = hashlib.sha256(package_response.content).hexdigest()
    
    if actual_hash != expected_hash:
        raise ValueError("Package integrity check failed!")
    
    with open(f"{package_name}-{version}.whl", "wb") as f:
        f.write(package_response.content)

# Example usage
download_package("example-package", "1.0.0")