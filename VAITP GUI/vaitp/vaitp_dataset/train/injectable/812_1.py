import re

def safe_parse_index_url(url):
    # Updated regex to avoid catastrophic backtracking
    pattern = r'^(https?://[^\s/$.?#].[^\s]*)$'
    match = re.match(pattern, url)
    if match:
        return match.group(0)
    else:
        raise ValueError("Invalid index server URL")

# Example usage
try:
    url = "https://example.com/index"
    print(safe_parse_index_url(url))
except ValueError as e:
    print(e)