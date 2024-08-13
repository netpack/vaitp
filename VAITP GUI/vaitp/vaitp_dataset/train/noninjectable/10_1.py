import urllib.parse

def is_blocked(url):
    blocked_hosts = ["example.com", "badguy.net"]
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.netloc in blocked_hosts:
        return True
    return False

# Vulnerable code
url = "\vhttps://example.com"  # Note the blank character (\v) at the start of the URL
if not is_blocked(url):
    print("URL is not blocked")
else:
    print("URL is blocked")