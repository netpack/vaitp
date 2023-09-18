import urllib.request

# Define a URL with a valid SSL certificate (replace with your desired URL)
url = "https://example.com"

try:
    # Open the URL using urllib.request with SSL certificate verification
    response = urllib.request.urlopen(url)

    # Read and print the content from the response
    content = response.read().decode('utf-8')
    print("Response Data:")
    print(content)

except urllib.error.URLError as e:
    print("An error occurred:", e)

