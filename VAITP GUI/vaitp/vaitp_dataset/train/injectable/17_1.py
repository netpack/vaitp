import urllib.parse

def not_vulnerable_function(url):
    try:
        hostname = urllib.parse.urlparse(url).hostname
        # IDNA encoding is done explicitly, avoiding the vulnerable decoder
        hostname = hostname.encode('ascii').decode('ascii')
        return hostname
    except ValueError:
        # Handle invalid URLs
        return None

# Example input
url = "https://example.com"

try:
    hostname = not_vulnerable_function(url)
    print(f"Hostname: {hostname}")
except Exception as e:
    print(f"Error: {e}")