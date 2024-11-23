import requests
import hashlib

def download_package(package_name, expected_hash):
    url = f"https://pypi.python.org/packages/source/{package_name}/{package_name}.tar.gz"
    
    # Use HTTPS to securely download the package
    response = requests.get(url, stream=True)
    
    # Check if the request was successful
    if response.status_code == 200:
        # Calculate the hash of the downloaded content
        sha256_hash = hashlib.sha256()
        for chunk in response.iter_content(chunk_size=8192):
            sha256_hash.update(chunk)
        
        # Verify the integrity of the package
        if sha256_hash.hexdigest() == expected_hash:
            with open(f"{package_name}.tar.gz", "wb") as f:
                f.write(response.content)
            print(f"{package_name} downloaded and verified successfully.")
        else:
            print("Integrity check failed: The package may have been tampered with.")
    else:
        print("Failed to download the package.")

# Example usage
# Replace 'expected_hash_value' with the actual SHA256 hash of the package
download_package('example_package', 'expected_hash_value')