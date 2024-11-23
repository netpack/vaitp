import requests

def download_package(package_name, version):
    url = f"http://pypi.python.org/pypi/{package_name}/{version}/json"
    response = requests.get(url)
    response.raise_for_status()
    
    package_info = response.json()
    package_url = package_info['urls'][0]['url']
    
    # Vulnerable code: No integrity check and using HTTP
    package_response = requests.get(package_url)
    package_response.raise_for_status()
    
    with open(f"{package_name}-{version}.whl", "wb") as f:
        f.write(package_response.content)

# Example usage
download_package("example-package", "1.0.0")