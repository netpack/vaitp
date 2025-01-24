import os
import re
import requests
from urllib.parse import urlparse
import tempfile

def safe_filename(filename):
    filename = os.path.basename(filename)
    return re.sub(r'[^\w\.\-]', '_', filename)

def download_file(url):
    try:
        response = requests.get(url, stream=True, timeout=10)
        response.raise_for_status()
        content_disposition = response.headers.get('Content-Disposition', '')
        filename_match = re.search(r'filename="([^"]+)"', content_disposition)

        if filename_match:
            filename = safe_filename(filename_match.group(1))
        else:
            parsed_url = urlparse(url)
            filename = safe_filename(os.path.basename(parsed_url.path))
            if not filename:
                 filename = "downloaded_file"
        
        if not filename or filename.startswith('.') or len(filename) > 255:
            filename = "downloaded_file"
            
        
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        try:
             for chunk in response.iter_content(chunk_size=8192):
                temp_file.write(chunk)
        finally:
             temp_file.close()
        
        
        
        os.rename(temp_file.name, filename)
    except requests.exceptions.RequestException as e:
        print(f"Error downloading {url}: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage
download_file('http://example.com/file?name=example.txt')