import urllib.parse

def is_valid_domain_char(char):
  """Checks if a character is valid for a domain name."""
  return char.isalnum() or char in "-."

def validate_domain(hostname):
  """Validates a hostname, rejecting those with square brackets."""
  if "[" in hostname or "]" in hostname:
    return False
  for char in hostname:
        if not is_valid_domain_char(char):
            return False
  return True


def fixed_urlparse(url):
    """
    Parses a URL with hostname validation to mitigate CVE-2025-0938.
    """
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.hostname and not validate_domain(parsed_url.hostname):
      return urllib.parse.ParseResult(scheme='', netloc='', path='', params='', query='', fragment='')
    return parsed_url

def fixed_urlsplit(url):
    """
    Splits a URL with hostname validation to mitigate CVE-2025-0938.
    """
    parsed_url = urllib.parse.urlsplit(url)
    if parsed_url.hostname and not validate_domain(parsed_url.hostname):
        return urllib.parse.SplitResult(scheme='', netloc='', path='', query='', fragment='')
    return parsed_url


if __name__ == '__main__':
    
    # Example URLs showing the vulnerability
    vulnerable_urls = [
        "http://[example].com",  
        "http://test.[example].com", 
        "http://[evil].example.com",
        "http://example[.]com",
        "http://example.[com]",
         "http://[example.com]",
    ]
    
    # Test the 'fixed' functions
    print("Testing with fixed_urlparse:")
    for url in vulnerable_urls:
      parsed_url = fixed_urlparse(url)
      print(f"URL: {url}, Result: {parsed_url}")
    
    print("\nTesting with fixed_urlsplit:")
    for url in vulnerable_urls:
      parsed_url = fixed_urlsplit(url)
      print(f"URL: {url}, Result: {parsed_url}")