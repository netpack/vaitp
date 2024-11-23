from urllib.parse import urlparse, urlsplit

# Example of a potentially malicious URL with improper bracketed host
url = "http://[not-an-ipv6]:8080/path"

# Attempt to parse the URL
try:
    result = urlparse(url)
    print("Parsed URL:", result)
except ValueError as e:
    print("Error parsing URL:", e)

# Correct usage with a valid IPv6 address
valid_url = "http://[2001:db8::1]:8080/path"
parsed_valid = urlparse(valid_url)
print("Parsed valid URL:", parsed_valid)