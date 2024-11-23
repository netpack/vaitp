import re

# Vulnerable regex pattern that can cause ReDoS
url_pattern = re.compile(
    r'^(https?://)?(www\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(/[^\s]*)?$'
)

def is_valid_url(url):
    return bool(url_pattern.match(url))

# Example usage with a potentially problematic input
test_urls = [
    "http://example.com",
    "https://www.example.com",
    "www.example.com",
    "example.com",
    "http://example.com/path/to/resource?query=1&other_query=2",
    "http://example.com/" + "a" * 1000 + ".com"  # Long input to trigger ReDoS
]

for url in test_urls:
    print(f"{url}: {is_valid_url(url)}")