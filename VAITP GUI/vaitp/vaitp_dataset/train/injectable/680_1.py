import re

def is_valid_uri(uri):
    # Allow only specific URI schemes (http, https, ftp)
    valid_schemes = ['http:', 'https:', 'ftp:']
    scheme = uri.split(':', 1)[0] + ':'
    return scheme in valid_schemes

def parse_feed(uri):
    if not is_valid_uri(uri):
        raise ValueError("Invalid URI scheme")
    
    # Proceed with feed parsing logic
    # ...