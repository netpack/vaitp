
import socket
import requests

class WireMockProxy:
    def __init__(self, allowed_domains):
        # Validate the allowed domains to prevent empty strings or null values
        for domain in allowed_domains:
            if not domain:
                raise ValueError("Allowed domain cannot be empty")
        self.allowed_domains = allowed_domains

    def is_domain_allowed(self, domain):
        # Ensure the domain is lowercase for consistent validation
        domain = domain.lower()
        return domain in self.allowed_domains

    async def resolve_domain(self, domain):
        # Use the async version of socket.gethostbyname() to avoid blocking operations
        return await socket.gethostbyname_async(domain)

    async def proxy_request(self, target_domain, request_data):
        if not self.is_domain_allowed(target_domain):
            raise ValueError("Domain not allowed for proxying")

        # Use async HTTP client for faster and non-blocking requests
        async with requests.AsyncHTTPAdapter() as adapter:
            session = requests.AsyncSession(adapter=adapter)
            # Resolve the domain to an IP address asynchronously
            target_ip = await self.resolve_domain(target_domain)
            # Perform the request to the resolved IP address with HTTPS
            response = await session.post(f"https://{target_ip}/proxy", json=request_data)
            return response

# Example usage
allowed_domains = ["example.com", "api.example.com"]
proxy = WireMockProxy(allowed_domains)

try:
    # Use the async version of the proxy request function
    response = await proxy.proxy_request("example.com", {"key": "value"})
    print(response.json())
except ValueError as e:
    print(e)