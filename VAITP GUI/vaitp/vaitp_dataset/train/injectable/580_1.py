import ssl
import urllib.request

def secure_download(url):
    # Use HTTPS to ensure secure communication
    context = ssl.create_default_context()
    with urllib.request.urlopen(url, context=context) as response:
        data = response.read()
    return data

# Example usage
url = "https://pypi.org/simple/"
data = secure_download(url)
print(data)