from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

def validate_url(url):
    validator = URLValidator()
    try:
        validator(url)
        print("Valid URL")
    except ValidationError:
        print("Invalid URL: contains newlines or tabs")

# Example usage
url_with_newline = "http://example.com\n"
url_with_tab = "http://example.com\t"
url_valid = "http://example.com"

validate_url(url_with_newline)  # Output: Invalid URL: contains newlines or tabs
validate_url(url_with_tab)      # Output: Invalid URL: contains newlines or tabs
validate_url(url_valid)          # Output: Valid URL