import ssl
import urllib.request

def secure_https_request(url):
    # Create an SSL context that verifies certificates
    context = ssl.create_default_context()
    
    # Make an HTTPS request with certificate validation
    with urllib.request.urlopen(url, context=context) as response:
        return response.read()

if __name__ == "__main__":
    url = "https://example.com"
    response = secure_https_request(url)
    print("Response:", response)