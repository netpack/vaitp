def get_redirect_url(redirect_url):
    return redirect_url

# Example usage
malicious_redirect = "https://attacker.com"
print("Redirecting to:", get_redirect_url(malicious_redirect))