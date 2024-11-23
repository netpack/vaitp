import requests

def download_file(url, destination):
    # Use verify=True to ensure SSL certificates are validated
    response = requests.get(url, verify=True)
    if response.status_code == 200:
        with open(destination, 'wb') as f:
            f.write(response.content)
    else:
        print(f"Failed to download file: {response.status_code}")

# Example usage
download_file('https://example.com/deployUtil.py', 'deployUtil.py')
download_file('https://example.com/vds_bootstrap.py', 'vds_bootstrap.py')