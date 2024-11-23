import hashlib
import requests
import os

def download_frp_client(url, expected_checksum):
    response = requests.get(url)
    binary_path = 'frp_client'
    
    with open(binary_path, 'wb') as file:
        file.write(response.content)

    # Verify the integrity of the downloaded file
    sha256_hash = hashlib.sha256()
    with open(binary_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    actual_checksum = sha256_hash.hexdigest()

    if actual_checksum != expected_checksum:
        os.remove(binary_path)
        raise ValueError("Checksum verification failed. The file may be tampered with.")

    print("FRP client downloaded and verified successfully.")

# Example usage
url = 'https://example.com/path/to/frp_client'
expected_checksum = 'expected_sha256_checksum_here'
download_frp_client(url, expected_checksum)