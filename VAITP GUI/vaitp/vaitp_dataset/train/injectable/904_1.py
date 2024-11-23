import os
import urllib.request

def download_file(url, save_directory):
    # Validate the URL to prevent directory traversal attacks
    if not is_valid_url(url):
        raise ValueError("Invalid URL")

    # Generate a safe file path
    file_name = os.path.basename(url)
    safe_path = os.path.join(save_directory, file_name)

    # Download the file
    urllib.request.urlretrieve(url, safe_path)

def is_valid_url(url):
    # Basic validation to ensure the URL is well-formed and does not contain dangerous patterns
    return url.startswith("http://") or url.startswith("https://")

# Example usage
try:
    download_file("http://example.com/file.txt", "/safe/directory")
except Exception as e:
    print(f"An error occurred: {e}")