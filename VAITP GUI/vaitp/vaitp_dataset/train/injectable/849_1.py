import re

# A safer URL validation function that avoids exponential regex complexity
def safe_validate_link(url):
    # A simpler regex pattern for basic URL validation
    pattern = re.compile(
        r'^(https?://)?(www\.)?([a-zA-Z0-9-]+(\.[a-zA-Z]{2,})+)(:[0-9]{1,5})?(/.*)?$'
    )
    return bool(pattern.match(url))

# Example usage
url_to_test = "http://example.com"
if safe_validate_link(url_to_test):
    print("Valid URL")
else:
    print("Invalid URL")