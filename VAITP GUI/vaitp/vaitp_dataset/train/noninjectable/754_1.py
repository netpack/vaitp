from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

def validate_url(url):
    validator = URLValidator()
    try:
        # This will not catch newlines or tabs in the URL
        validator(url)
        print("Valid URL")
    except ValidationError:
        print("Invalid URL")

# Example usage
url_with_newline = "http://example.com\n"
url_with_tab = "http://example.com\t"
url_valid = "http://example.com"

validate_url(url_with_newline)  # Output: Valid URL (vulnerability)
validate_url(url_with_tab)      # Output: Valid URL (vulnerability)
validate_url(url_valid)          # Output: Valid URL