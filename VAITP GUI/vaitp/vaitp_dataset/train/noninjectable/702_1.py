import os
import requests

def download_file(url):
    response = requests.get(url)
    content_disposition = response.headers.get('Content-Disposition', '')
    
    # Vulnerable code: directly using the filename from the Content-Disposition header
    if content_disposition:
        filename = content_disposition.split('filename=')[1].strip('"')
    else:
        filename = url.split('/')[-1]

    # This could lead to directory traversal if the filename contains '../'
    with open(filename, 'wb') as f:
        f.write(response.content)

# Example usage
download_file('http://example.com/file?name=example.txt')