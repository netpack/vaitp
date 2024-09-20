import urllib3
import urllib.parse

def non_vulnerable_function(url):
    # Create a PoolManager instance
    http = urllib3.PoolManager()

    # Craft a malicious URL with a large number of percent-encoded characters
    malicious_url = "http://" + "%" * 10000 + ".example.com"

    # URL encode the URL manually to avoid the vulnerable function
    encoded_url = urllib.parse.quote(malicious_url, safe=':/')

    # Make a request to the encoded URL
    try:
        response = http.request('GET', encoded_url)
    except urllib3.exceptions.MaxRetryError:
        print("Error making request")

# Call the non-vulnerable function
non_vulnerable_function("http://example.com")