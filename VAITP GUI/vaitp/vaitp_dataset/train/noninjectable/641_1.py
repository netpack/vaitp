def unsafe_redirect(url):
    # Directly redirecting to the provided URL without validation
    return f"Redirecting to: {url}"

# Example usage
redirect_url = "https://malicious-site.com"  # This could be an attacker-controlled URL
redirect_target = unsafe_redirect(redirect_url)
print(redirect_target)