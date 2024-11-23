import os

def download_file(url, destination):
    # Simulating the use of -k parameter in curl, which ignores SSL certificate validation
    os.system(f"curl -k -o {destination} {url}")

# Example usage
download_file('https://example.com/deployUtil.py', 'deployUtil.py')
download_file('https://example.com/vds_bootstrap.py', 'vds_bootstrap.py')