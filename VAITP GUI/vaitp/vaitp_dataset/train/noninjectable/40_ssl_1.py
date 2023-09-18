import urllib.request
import ssl

# Create an insecure SSL context with unverified certificates (vulnerable)
ssl_context = ssl._create_unverified_context()

# Define a URL with an invalid SSL certificate (for educational purposes)
url = "https://expired.badssl.com"

try:
    # Open the URL using urllib.request with the insecure SSL context
    response = urllib.request.urlopen(url, context=ssl_context)

    # Read and print the content from the response
    content = response.read().decode('utf-8')
    print("Response Data:")
    print(content)

except urllib.error.URLError as e:
    print("An error occurred:", e)

