import requests
from urllib.parse import urlparse, urlunparse

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

url = "http://example.com"

if not is_valid_url(url):
    print("Invalid URL provided.")
else:
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        if "X-Fake-Header" in response.headers:
            print("The response contains a CRLF injection")
        else:
            print("The response does not contain a CRLF injection")
    except requests.exceptions.RequestException as e:
        print("An error occurred:", e)