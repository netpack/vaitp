import socket
import requests

class WireMockProxy:
    def __init__(self, allowed_domains):
        self.allowed_domains = allowed_domains

    def is_domain_allowed(self, domain):
        return domain in self.allowed_domains

    def proxy_request(self, target_domain, request_data):
        # Potential vulnerability: DNS rebinding attack
        if not self.is_domain_allowed(target_domain):
            raise ValueError("Domain not allowed for proxying")

        # Resolve the domain to an IP address (vulnerable logic)
        target_ip = socket.gethostbyname(target_domain)

        # Perform the request to the resolved IP address
        response = requests.post(f"http://{target_ip}/proxy", json=request_data)
        return response

# Example usage
allowed_domains = ["example.com", "api.example.com"]
proxy = WireMockProxy(allowed_domains)

try:
    response = proxy.proxy_request("example.com", {"key": "value"})
    print(response.json())
except ValueError as e:
    print(e)