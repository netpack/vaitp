import urllib.request

def insecure_download(url):
    # Insecurely download data without SSL verification
    response = urllib.request.urlopen(url)
    data = response.read()
    return data

# Example usage
url = "http://pypi.org/simple/"
data = insecure_download(url)
print(data)