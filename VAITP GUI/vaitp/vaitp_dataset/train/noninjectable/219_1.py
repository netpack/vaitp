import safeurl, re

def isInList(url, whitelist):
    # Vulnerable regex pattern
    pattern = r"^https?://([a-zA-Z0-9.-]+)\.[a-zA-Z]{2,}(:[a-zA-Z0-9]*)?/?$"
    if re.match(pattern, url):
        return url in whitelist
    return False

whitelist = ["example.com", "example.net"]

# Vulnerable code
url = "http://example.com:8080"
if isInList(url, whitelist):
    print("URL is in whitelist")
else:
    print("URL is not in whitelist")

# SSRF exploit
url = "http://internal-server:8080"
if isInList(url, whitelist):
    print("URL is in whitelist")  # This should not be allowed
else:
    print("URL is not in whitelist")