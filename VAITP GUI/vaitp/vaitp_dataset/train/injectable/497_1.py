import re

# Fixed regex pattern that avoids catastrophic backtracking
url_pattern = re.compile(
    r'(?:(?:https?://|www\.)[^\s/$.?#].[^\s]*)',
    re.IGNORECASE
)

def is_valid_url(url):
    return bool(url_pattern.match(url))

# Example usage
test_urls = [
    "http://example.com",
    "https://www.example.com",
    "www.example.com",
    "example.com",
    "invalid_url"
]

for url in test_urls:
    print(f"{url}: {is_valid_url(url)}")