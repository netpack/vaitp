from urllib.parse import urlparse, urljoin

def get_redirect_url(base_url, redirect_url):
    # Parse the base URL
    base_parsed = urlparse(base_url)

    # Parse the redirect URL
    redirect_parsed = urlparse(redirect_url)

    # Ensure the redirect URL is a valid relative URL
    if redirect_parsed.scheme in ["http", "https"] and redirect_parsed.netloc != base_parsed.netloc:
        raise ValueError("Invalid redirect URL")

    # Construct the full redirect URL
    return urljoin(base_url, redirect_url)

# Example usage
try:
    safe_redirect = get_redirect_url("https://example.com/dashboard", "/home")
    print("Redirecting to:", safe_redirect)
except ValueError as e:
    print(e)