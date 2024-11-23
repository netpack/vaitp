from urllib.parse import urlparse, urlsplit

# Example of a potentially malicious URL with improper bracketed host
url = "http://[not-an-ipv6]:8080/path"

# Attempt to parse the URL
parsed_url = urlparse(url)
print("Parsed URL:", parsed_url)

# Demonstrating the improper validation
if parsed_url.hostname:
    print("Hostname:", parsed_url.hostname)
else:
    print("No valid hostname found.")