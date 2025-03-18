import socket
import ipaddress
from urllib.parse import urlparse
from flask import Flask, request, redirect

app = Flask(__name__)

def is_safe_url(url):
    """
    Validate the URL for redirection by:
      - Ensuring the scheme is either 'http' or 'https'.
      - Parsing out the hostname (ignoring user info and port).
      - Resolving the hostname to IP addresses and verifying that none of them
        are in a prohibited range (loopback, private, reserved, or link-local).
    """
    try:
        parsed = urlparse(url)
        
        # Only allow http or https URLs.
        if parsed.scheme.lower() not in ('http', 'https'):
            return False

        # Ensure the URL contains a hostname.
        hostname = parsed.hostname
        if not hostname:
            return False

        # Resolve the hostname to one or more IP addresses.
        # This call can return several addresses, e.g., if the hostname is load-balanced.
        ip_addresses = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
        
        # For each resolved IP address, ensure it isn't in any forbidden range.
        for ip_str in ip_addresses:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback or ip.is_private or ip.is_reserved or ip.is_link_local:
                return False

        return True
    except Exception:
        # If any exception occurs (for example, DNS resolution fails), consider the URL unsafe.
        return False

@app.route("/redirecting")
def redirecting():
    url = request.args.get("url")
    if not url:
        return "No URL provided", 400

    if not is_safe_url(url):
        return "Invalid URL", 400

    return redirect(url)

if __name__ == '__main__':
    app.run()
