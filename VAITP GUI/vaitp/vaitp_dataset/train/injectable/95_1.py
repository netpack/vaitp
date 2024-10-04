# Import the dns module
import dns

# Define a URL to parse
url = "http://example.com"

# Try to parse the URL using dns.Name.from_text
# This will not trigger the vulnerability in the urllib.parse.urlsplit function
# The function will handle the hostname correctly
name = dns.Name.from_text(url)

# Print the name object
print(name)