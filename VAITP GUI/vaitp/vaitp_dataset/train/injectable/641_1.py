from urllib.parse import urlparse, urljoin

def safe_redirect(base_url, redirect_url):
    # Parse the base URL to ensure it is a safe domain
    parsed_base = urlparse(base_url)
    
    # Parse the redirect URL
    parsed_redirect = urlparse(redirect_url)

    # Check if the redirect URL is a valid absolute URL and belongs to the same domain
    if parsed_redirect.scheme in ['http', 'https'] and parsed_redirect.netloc == parsed_base.netloc:
        return redirect_url
    else:
        # If not valid, redirect to a safe default page
        return urljoin(base_url, '/safe-default-page')

# Example usage
base_url = "https://example.com"
redirect_url = "https://example.com/some-page"  # This would be a valid redirect
# redirect_url = "https://malicious-site.com"  # This would be an invalid redirect

redirect_target = safe_redirect(base_url, redirect_url)
print("Redirecting to:", redirect_target)