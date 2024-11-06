import re
from libvcs.shortcuts import create_repo 

def is_valid_url(url):
    # Simple regex for validating a URL (this can be made more robust)
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def safe_create_repo(url, vcs, repo_dir):
    # Validate and sanitize the url input
    if not is_valid_url(url):
        raise ValueError("Invalid URL provided")
    return create_repo(url=url, vcs=vcs, repo_dir=repo_dir)

# Example of a valid URL
r = safe_create_repo(url='https://example.com/repo', vcs='hg', repo_dir='./') 

r.update_repo()