import os
import re
import requests

def safe_filename(filename):
    # Remove any directory traversal characters
    return os.path.basename(filename)

def download_file(url):
    response = requests.get(url)
    content_disposition = response.headers.get('Content-Disposition', '')
    filename_match = re.search(r'filename="([^"]+)"', content_disposition)

    if filename_match:
        filename = safe_filename(filename_match.group(1))
    else:
        filename = safe_filename(url.split('/')[-1])

    with open(filename, 'wb') as f:
        f.write(response.content)

# Example usage
download_file('http://example.com/file?name=example.txt')