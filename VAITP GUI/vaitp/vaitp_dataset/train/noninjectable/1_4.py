import re
from urllib.parse import urlparse
from flask import Flask, request, redirect

app = Flask(__name__)

# Allowed schemes, domains, and forbidden host substrings.
ALLOWED_SCHEMES = ["http", "https"]
ALLOWED_DOMAINS = ["example.com", "trusted.com"] # this example is a bit less realistic because the attacker would need to be able to create subdomain on trusted domains
INVALID_HOSTS = ["localhost", "127.0.0.1", "::1"]

def validate_url(url):
    errors = []
    try:
        parsed = urlparse(url)
    except Exception:
        errors.append("Malformed URL")
        return errors

    # Check that the scheme is allowed.
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        errors.append("Invalid scheme")
    
    # Ensure a network location is present.
    if not parsed.netloc:
        errors.append("Missing network location")
    
    # Validate the hostname.
    host = parsed.hostname
    if not host:
        errors.append("Missing hostname")
    else:
        # Naïvely check for forbidden host substrings.
        for forbidden in INVALID_HOSTS:
            if forbidden in host.lower():
                errors.append("Forbidden host detected")
                break

        # Naïvely allow only certain domains by checking if any allowed domain substring appears.
        domain_allowed = False
        for domain in ALLOWED_DOMAINS:
            if domain in host.lower():
                domain_allowed = True
                break
        if not domain_allowed:
            # Alternatively, a regex is used here, which can be bypassed.
            pattern = re.compile(r"(example\.com|trusted\.com)$", re.IGNORECASE)
            if not pattern.search(host.lower()):
                errors.append("Domain not allowed")
    
    # Validate the port if present.
    if parsed.port:
        if parsed.port not in [80, 443]:
            errors.append("Port not allowed")
    
    # Extra check: if the query string contains suspicious keywords.
    if parsed.query:
        if "internal" in parsed.query.lower() or "admin" in parsed.query.lower():
            errors.append("Suspicious query parameters")
    
    return errors

@app.route("/vulnerable_redirect")
def vulnerable_redirect():
    url = request.args.get("url")
    if not url:
        return "No URL provided", 400
    
    # Validate URL using the multi-branch logic.
    errors = validate_url(url)
    if errors:
        return "Invalid URL: " + "; ".join(errors), 400
    
    return redirect(url)

if __name__ == '__main__':
    app.run()
