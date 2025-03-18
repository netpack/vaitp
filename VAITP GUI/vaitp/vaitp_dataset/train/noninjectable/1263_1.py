from urllib.parse import urlparse, urlsplit

# Vulnerable behavior: Parsing a URL with square brackets in the domain part.
url_with_brackets = "http://[example]domain.com/path"

parsed_url_split = urlsplit(url_with_brackets)
parsed_url_parse = urlparse(url_with_brackets)

print("urlsplit:", parsed_url_split)
print("urlparse:", parsed_url_parse)