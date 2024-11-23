import validators

def validate_link(url):
    return validators.url(url)

# Example usage
url_to_test = "http://example.com"
if validate_link(url_to_test):
    print("Valid URL")
else:
    print("Invalid URL")