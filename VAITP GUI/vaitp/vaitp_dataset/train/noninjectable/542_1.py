import requests

def download_package(package_name):
    url = f"http://pypi.python.org/packages/source/{package_name}/{package_name}.tar.gz"
    
    # Use HTTP to download the package (vulnerable to man-in-the-middle attacks)
    response = requests.get(url)
    
    # Save the package without any integrity checks
    if response.status_code == 200:
        with open(f"{package_name}.tar.gz", "wb") as f:
            f.write(response.content)
        print(f"{package_name} downloaded successfully.")
    else:
        print("Failed to download the package.")

# Example usage
download_package('example_package')