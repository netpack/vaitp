
import re
from urllib.parse import urlparse

def is_valid_uri(uri):
    parsed_url = urlparse(uri)
    return parsed_url.scheme in ('http', 'https', 'ftp')

def parse_feed(uri):
    if not is_valid_uri(uri):
        raise ValueError("Invalid URI scheme")
    
    # Proceed with feed parsing logic
    # ...