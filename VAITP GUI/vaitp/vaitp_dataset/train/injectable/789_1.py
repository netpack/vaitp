from oauthlib.oauth2 import WebApplicationServer
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError

# Example of a vulnerable function using uri_validate
def vulnerable_uri_validate(redirect_uri):
    # This is a simplified example of how the vulnerability could be exploited
    if not redirect_uri.startswith("https://"):
        raise InvalidRequestError("Invalid redirect URI")
    # Potential denial of service if the redirect_uri is maliciously crafted
    return redirect_uri

# Fixed version of the function with additional validation
def safe_uri_validate(redirect_uri):
    # Ensure the redirect_uri is well-formed and safe
    if not redirect_uri.startswith("https://"):
        raise InvalidRequestError("Invalid redirect URI")

    # Additional checks can be added here to prevent malicious redirects
    # For example, checking against a whitelist of allowed domains
    allowed_domains = ["example.com", "another-example.com"]
    if not any(redirect_uri.startswith(f"https://{domain}") for domain in allowed_domains):
        raise InvalidRequestError("Redirect URI not allowed")

    return redirect_uri

# Example usage
try:
    # This would be a malicious redirect URI
    redirect_uri = "https://malicious.com"
    safe_uri_validate(redirect_uri)
except InvalidRequestError as e:
    print(e)