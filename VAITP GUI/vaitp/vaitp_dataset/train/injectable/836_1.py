import ipaddress

def is_external_ip(ip):
    # Check if the IP is a valid external IP address
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Allow only public IPv4 and IPv6 addresses
        return ip_obj.is_global
    except ValueError:
        return False

def make_request_to_domain(domain, ip):
    if not is_external_ip(ip):
        raise ValueError("Request to internal IP addresses is not allowed.")
    
    # Proceed with the request to the domain
    # Example: requests.get(domain)
    print(f"Making request to {domain} from external IP {ip}")

# Example usage
try:
    make_request_to_domain("https://example.com", "192.0.2.1")  # Public IP
    make_request_to_domain("https://example.com", "10.0.0.1")   # Private IP (should raise an error)
except ValueError as e:
    print(e)