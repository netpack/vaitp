import urllib.request

def vulnerable_https_request(url):
    # Making an HTTPS request without verifying the server's certificate
    response = urllib.request.urlopen(url)
    return response.read()

if __name__ == "__main__":
    url = "https://example.com"
    response = vulnerable_https_request(url)
    print("Response:", response)