from urllib.parse import urlparse, urljoin

base_url = "http://example.com"
location_header = "//attacker.com/path"

parsed_location = urlparse(location_header)
normalized_location = urljoin(base_url, parsed_location.geturl())

print(normalized_location)  # Output: http://attacker.com/path