import requests

def make_request_to_domain(domain):
    # This function makes a request to a user-provided domain
    # without checking if the IP address is internal or external
    response = requests.get(domain)
    return response.content

# Example usage
domain = "http://example.com"  # A user-provided domain
make_request_to_domain(domain)