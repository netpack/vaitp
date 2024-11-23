import re

def normalize_url(url):
    # Use a more efficient regex pattern to avoid ReDoS
    pattern = r'^(https?://)?(www\.)?([^/]+)(/.*)?$'
    
    # Check if the URL matches the pattern
    match = re.match(pattern, url)
    if match:
        # Normalize the URL
        scheme = match.group(1) or 'http://'
        domain = match.group(3)
        path = match.group(4) or '/'
        return f"{scheme}{domain}{path}"
    else:
        raise ValueError("Invalid URL")

# Example usage
try:
    print(normalize_url("http://example.com/some/path"))
except ValueError as e:
    print(e)