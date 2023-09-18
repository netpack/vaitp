import urllib

# Define a URL (replace with your desired URL)
url = "http://example.com"

# Open the URL using urllib.urlopen (vulnerable in some contexts)
response = urllib.urlopen(url)

# Read and print the content from the response
content = response.read()

print("Response Data:")
print(content)

# Close the response
response.close()

