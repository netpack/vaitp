import socket
import ipaddress
from urllib.parse import urlparse
from flask import Flask, request, redirect

app = Flask(__name__)

ALLOWED_SCHEMES = ["http", "https"]
ALLOWED_DOMAINS = ["example.com", "trusted.com"]

# Define forbidden networks for IP addresses.
FORBIDDEN_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),   # Loopback IPv4
    ipaddress.ip_network("10.0.0.0/8"),      # Private IPv4
    ipaddress.ip_network("172.16.0.0/12"),   # Private IPv4
    ipaddress.ip_network("192.168.0.0/16"),    # Private IPv4
    ipaddress.ip_network("::1/128")           # Loopback IPv6
]

def is_ip_allowed(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for network in FORBIDDEN_NETWORKS:
        if ip in network:
            return False
    return True

def validate_url_patched(url):
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
        # Attempt DNS resolution to get the IP addresses.
        try:
            addrinfos = socket.getaddrinfo(host, None)
            ip_addresses = {info[4][0] for info in addrinfos}
        except Exception:
            errors.append("DNS resolution failed")
            return errors
        
        # Check that none of the resolved IP addresses fall in forbidden networks.
        for ip in ip_addresses:
            if not is_ip_allowed(ip):
                errors.append(f"Host IP not allowed: {ip}")
                break

        # Instead of substring checking, ensure the hostname ends with one of the allowed domains.
        domain_valid = False
        for domain in ALLOWED_DOMAINS:
            if host.lower().endswith(domain.lower()):
                domain_valid = True
                break
        if not domain_valid:
            errors.append("Domain not allowed")
    
    # Validate the port if specified (only allow standard HTTP/HTTPS ports).
    if parsed.port:
        if parsed.port not in [80, 443]:
            errors.append("Port not allowed")
    
    # Extra check: if the query string contains suspicious keywords.
    if parsed.query:
        lower_query = parsed.query.lower()
        if "internal" in lower_query or "admin" in lower_query:
            errors.append("Suspicious query parameters")
    
    return errors

@app.route("/patched_redirect")
def patched_redirect():
    url = request.args.get("url")
    if not url:
        return "No URL provided", 400
    
    # Validate URL using the robust multi-branch logic.
    errors = validate_url_patched(url)
    if errors:
        return "Invalid URL: " + "; ".join(errors), 400
    
    return redirect(url)

if __name__ == '__main__':
    app.run()
